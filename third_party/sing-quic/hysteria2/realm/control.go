package realm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/netip"
	"net/url"
	"strings"

	"github.com/metacubex/http"
	E "github.com/metacubex/sing/common/exceptions"
	F "github.com/metacubex/sing/common/format"
)

type ControlClient struct {
	serverURL  string
	token      string
	httpClient *http.Client
}

func NewControlClient(serverURL string, token string, httpClient *http.Client) (*ControlClient, error) {
	if serverURL == "" {
		return nil, E.New("control server URL is required")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &ControlClient{
		serverURL:  strings.TrimRight(serverURL, "/"),
		token:      token,
		httpClient: httpClient,
	}, nil
}

type StatusError struct {
	StatusCode int
	ErrorCode  string
	Message    string
}

func (e *StatusError) Error() string {
	if e.Message != "" {
		return F.ToString("control ", e.StatusCode, "/", e.ErrorCode, ": ", e.Message)
	}
	return F.ToString("control ", e.StatusCode, "/", e.ErrorCode)
}

type Registration struct {
	SessionID string `json:"session_id"`
	TTL       int    `json:"ttl"`
}

type ConnectResponse struct {
	Addresses     []netip.AddrPort
	PunchMetadata PunchMetadata
}

type PunchEvent struct {
	Addresses     []netip.AddrPort
	PunchMetadata PunchMetadata
}

type registerRequest struct {
	Addresses []netip.AddrPort `json:"addresses"`
}

type heartbeatRequest struct {
	Addresses []netip.AddrPort `json:"addresses,omitempty"`
}

type heartbeatResponse struct {
	TTL int `json:"ttl"`
}

type punchMetadataWire struct {
	Addresses []netip.AddrPort `json:"addresses"`
	Nonce     string           `json:"nonce"`
	Obfs      string           `json:"obfs"`
}

type connectResponseRequest struct {
	Addresses []netip.AddrPort `json:"addresses"`
}

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func (c *ControlClient) realmURL(realmID string, subPath string) string {
	return c.serverURL + "/v1/" + url.PathEscape(realmID) + subPath
}

func (c *ControlClient) doJSON(ctx context.Context, method, requestURL, token string, requestBody, responseBody any) error {
	var bodyReader io.Reader
	if requestBody != nil {
		body, err := json.Marshal(requestBody)
		if err != nil {
			return E.Cause(err, "marshal request")
		}
		bodyReader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL, bodyReader)
	if err != nil {
		return E.Cause(err, "create request")
	}
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	err = checkStatus(response)
	if err != nil {
		return err
	}
	if responseBody != nil {
		err = json.NewDecoder(response.Body).Decode(responseBody)
		if err != nil {
			return E.Cause(err, "decode response")
		}
	}
	return nil
}

func (c *ControlClient) Register(ctx context.Context, realmID string, addresses []netip.AddrPort) (*Registration, error) {
	var registration Registration
	err := c.doJSON(ctx, http.MethodPost, c.realmURL(realmID, ""), c.token, registerRequest{Addresses: addresses}, &registration)
	if err != nil {
		return nil, E.Cause(err, "register")
	}
	return &registration, nil
}

func (c *ControlClient) Deregister(ctx context.Context, realmID string, sessionToken string) error {
	err := c.doJSON(ctx, http.MethodDelete, c.realmURL(realmID, ""), sessionToken, nil, nil)
	if err != nil {
		return E.Cause(err, "deregister")
	}
	return nil
}

func (c *ControlClient) Heartbeat(ctx context.Context, realmID string, sessionToken string, addresses []netip.AddrPort) (int, error) {
	var result heartbeatResponse
	err := c.doJSON(ctx, http.MethodPost, c.realmURL(realmID, "/heartbeat"), sessionToken, heartbeatRequest{Addresses: addresses}, &result)
	if err != nil {
		return 0, E.Cause(err, "heartbeat")
	}
	return result.TTL, nil
}

func (c *ControlClient) Connect(ctx context.Context, realmID string, addresses []netip.AddrPort, metadata PunchMetadata) (*ConnectResponse, error) {
	var raw punchMetadataWire
	err := c.doJSON(ctx, http.MethodPost, c.realmURL(realmID, "/connect"), c.token, punchMetadataWire{
		Addresses: addresses,
		Nonce:     hex.EncodeToString(metadata.Nonce[:]),
		Obfs:      hex.EncodeToString(metadata.ObfuscationKey[:]),
	}, &raw)
	if err != nil {
		return nil, E.Cause(err, "connect")
	}
	metaOut, err := decodeWireMetadata(raw.Nonce, raw.Obfs)
	if err != nil {
		return nil, E.Cause(err, "decode connect response metadata")
	}
	return &ConnectResponse{Addresses: raw.Addresses, PunchMetadata: metaOut}, nil
}

func (c *ControlClient) ConnectResponse(ctx context.Context, realmID string, sessionToken string, nonce string, addresses []netip.AddrPort) error {
	err := c.doJSON(ctx, http.MethodPost, c.realmURL(realmID, "/connects/"+url.PathEscape(nonce)), sessionToken, connectResponseRequest{Addresses: addresses}, nil)
	if err != nil {
		return E.Cause(err, "connect response")
	}
	return nil
}

type EventStream struct {
	response *http.Response
	scanner  *bufio.Scanner
}

func (c *ControlClient) Events(ctx context.Context, realmID string, sessionToken string) (*EventStream, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.realmURL(realmID, "/events"), nil)
	if err != nil {
		return nil, E.Cause(err, "create events request")
	}
	if sessionToken != "" {
		request.Header.Set("Authorization", "Bearer "+sessionToken)
	}
	request.Header.Set("Accept", "text/event-stream")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, E.Cause(err, "open event stream")
	}
	err = checkStatus(response)
	if err != nil {
		response.Body.Close()
		return nil, err
	}
	return &EventStream{
		response: response,
		scanner:  bufio.NewScanner(response.Body),
	}, nil
}

func (s *EventStream) Next() (*PunchEvent, error) {
	var eventType string
	var dataBuilder strings.Builder
	for s.scanner.Scan() {
		line := s.scanner.Text()
		if line == "" {
			if eventType == "punch" && dataBuilder.Len() > 0 {
				var raw punchMetadataWire
				err := json.Unmarshal([]byte(dataBuilder.String()), &raw)
				if err != nil {
					eventType = ""
					dataBuilder.Reset()
					continue
				}
				metadata, err := decodeWireMetadata(raw.Nonce, raw.Obfs)
				if err != nil {
					eventType = ""
					dataBuilder.Reset()
					continue
				}
				return &PunchEvent{Addresses: raw.Addresses, PunchMetadata: metadata}, nil
			}
			eventType = ""
			dataBuilder.Reset()
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch field {
		case "event":
			eventType = value
		case "data":
			if dataBuilder.Len() > 0 {
				dataBuilder.WriteByte('\n')
			}
			dataBuilder.WriteString(value)
		}
	}
	err := s.scanner.Err()
	if err != nil {
		return nil, E.Cause(err, "read event stream")
	}
	return nil, io.EOF
}

func (s *EventStream) Close() error {
	return s.response.Body.Close()
}

func decodeWireMetadata(nonceHex string, obfsHex string) (PunchMetadata, error) {
	var metadata PunchMetadata
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return metadata, E.Cause(err, "decode nonce")
	}
	if len(nonce) != len(metadata.Nonce) {
		return metadata, E.New("invalid nonce length: ", len(nonce))
	}
	obfs, err := hex.DecodeString(obfsHex)
	if err != nil {
		return metadata, E.Cause(err, "decode obfs")
	}
	if len(obfs) != len(metadata.ObfuscationKey) {
		return metadata, E.New("invalid obfs length: ", len(obfs))
	}
	copy(metadata.Nonce[:], nonce)
	copy(metadata.ObfuscationKey[:], obfs)
	return metadata, nil
}

const maxErrorBodySize = 64 * 1024

func checkStatus(response *http.Response) error {
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	var errorResult errorResponse
	_ = json.NewDecoder(io.LimitReader(response.Body, maxErrorBodySize)).Decode(&errorResult)
	return &StatusError{
		StatusCode: response.StatusCode,
		ErrorCode:  errorResult.Error,
		Message:    errorResult.Message,
	}
}
