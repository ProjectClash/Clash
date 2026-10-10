//go:build darwin

package clash

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/ProjectClash/Clash/log"

	D "github.com/miekg/dns"
)

const mdnsSupported = true

const (
	mdnsSocketPath    = "/var/run/mDNSResponder"
	mdnsSocketEnv     = "DNSSD_UDS_PATH"
	mdnsVersion       = 1
	mdnsHeaderLength  = 28
	mdnsOpConnection  = 1
	mdnsOpQuery       = 8
	mdnsOpCancel      = 63
	mdnsOpQueryReply  = 68
	mdnsOpAsyncError  = 73
	mdnsMaxReplyBytes = 1 << 20

	mdnsFlagMoreComing          = 0x1
	mdnsFlagAdd                 = 0x2
	mdnsFlagReturnIntermediates = 0x1000
	mdnsFlagShareConnection     = 0x4000
	mdnsFlagTimeout             = 0x10000

	mdnsIPCFlagNoErrorSocket = 0x4

	mdnsErrNoError      = 0
	mdnsErrNoSuchName   = -65538
	mdnsErrNoSuchRecord = -65554
	mdnsErrTimeout      = -65568

	mdnsQueryContext = 1
)

const mdnsQueryTimeout = 5 * time.Second

var errMDNSNoSuchRecord = errors.New("mdns: no such record")

var mdnsConcurrency = make(chan struct{}, 32)

func exchangeMulticastDNS(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	if len(m.Question) == 0 {
		return nil, errors.New("mdns: query has no question")
	}
	select {
	case mdnsConcurrency <- struct{}{}:
		defer func() { <-mdnsConcurrency }()
	default:
		log.Warnln("[mDNS] %s refused: too many queries in flight (cap %d)", m.Question[0].Name, cap(mdnsConcurrency))
		return nil, errors.New("mdns: too many queries in flight")
	}
	question := m.Question[0]
	ctx, cancel := context.WithTimeout(ctx, mdnsQueryTimeout)
	defer cancel()

	started := time.Now()
	conn, err := dialMDNSResponder(ctx)
	if err != nil {
		log.Warnln("[mDNS] %s %s unreachable in %s: %v", question.Name, dnsTypeName(question.Qtype), time.Since(started).Round(time.Millisecond), err)
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if _, err = conn.Write(buildMDNSQuery(question.Name, question.Qtype, question.Qclass)); err != nil {
		return nil, fmt.Errorf("mdns: write query: %w", err)
	}

	answers, err := readMDNSAnswers(conn, question)
	if err != nil && ctx.Err() != nil {
		err = fmt.Errorf("mdns: query timeout for %s after %s", question.Name, mdnsQueryTimeout)
	}
	_, _ = conn.Write(appendMDNSHeader(make([]byte, 0, mdnsHeaderLength), mdnsOpCancel, 0, mdnsQueryContext, 0))
	elapsed := time.Since(started).Round(time.Millisecond)
	if err != nil {
		if errors.Is(err, errMDNSNoSuchRecord) {
			log.Infoln("[mDNS] %s %s -> 0 answer(s) in %s", question.Name, dnsTypeName(question.Qtype), elapsed)
			return emptyMDNSReply(m), nil
		}
		log.Warnln("[mDNS] %s %s failed in %s: %v", question.Name, dnsTypeName(question.Qtype), elapsed, err)
		return nil, err
	}
	log.Infoln("[mDNS] %s %s -> %d answer(s) in %s", question.Name, dnsTypeName(question.Qtype), len(answers), elapsed)
	reply := emptyMDNSReply(m)
	reply.Answer = answers
	return reply, nil
}

func dnsTypeName(qtype uint16) string {
	if name, ok := D.TypeToString[qtype]; ok {
		return name
	}
	return "TYPE" + strconv.Itoa(int(qtype))
}

func emptyMDNSReply(m *D.Msg) *D.Msg {
	reply := new(D.Msg)
	reply.SetReply(m)
	reply.RecursionAvailable = true
	return reply
}

func dialMDNSResponder(ctx context.Context) (net.Conn, error) {
	path := os.Getenv(mdnsSocketEnv)
	if path == "" {
		path = mdnsSocketPath
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("mdns: connect %s: %w", path, err)
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()

	if _, err = conn.Write(appendMDNSHeader(make([]byte, 0, mdnsHeaderLength), mdnsOpConnection, 0, 0, 0)); err != nil {
		conn.Close()
		return nil, contextOrError(ctx, fmt.Errorf("mdns: write connection request: %w", err))
	}
	var status [4]byte
	if _, err = io.ReadFull(conn, status[:]); err != nil {
		conn.Close()
		return nil, contextOrError(ctx, fmt.Errorf("mdns: read connection status: %w", err))
	}
	if code := int32(binary.BigEndian.Uint32(status[:])); code != mdnsErrNoError {
		conn.Close()
		return nil, fmt.Errorf("mdns: connection request failed: error %d", code)
	}
	return conn, nil
}

func contextOrError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}

func readMDNSAnswers(conn net.Conn, question D.Question) ([]D.RR, error) {
	var (
		answers    []D.RR
		haveAnswer bool
		lastErr    error
	)
	finish := func() ([]D.RR, error) {
		if len(answers) != 0 {
			return answers, nil
		}
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, errMDNSNoSuchRecord
	}
	for {
		operation, _, data, err := readMDNSReply(conn)
		if err != nil {
			if len(answers) != 0 {
				return answers, nil
			}
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, fmt.Errorf("mdns: read reply: %w", err)
		}
		switch operation {
		case mdnsOpAsyncError:
			if len(data) >= 12 {
				if len(answers) != 0 {
					return answers, nil
				}
				return nil, mdnsError(question.Name, int32(binary.BigEndian.Uint32(data[8:12])))
			}
		case mdnsOpQueryReply:
			reply, parseErr := parseMDNSReply(data)
			if parseErr != nil {
				return nil, parseErr
			}
			if reply.errorCode != mdnsErrNoError {
				lastErr = mdnsError(question.Name, reply.errorCode)
				if reply.flags&mdnsFlagMoreComing == 0 {
					return finish()
				}
				continue
			}
			if reply.flags&mdnsFlagAdd != 0 && len(reply.rdata) != 0 {
				if record, buildErr := buildMDNSRecord(reply); buildErr == nil {
					answers = append(answers, record)
					if record.Header().Rrtype == question.Qtype {
						haveAnswer = true
					}
				}
			}
			if reply.flags&mdnsFlagMoreComing == 0 && haveAnswer {
				return answers, nil
			}
		}
	}
}

func appendMDNSHeader(buffer []byte, operation uint32, dataLength int, clientContext uint64, ipcFlags uint32) []byte {
	buffer = binary.BigEndian.AppendUint32(buffer, mdnsVersion)
	buffer = binary.BigEndian.AppendUint32(buffer, uint32(dataLength))
	buffer = binary.BigEndian.AppendUint32(buffer, ipcFlags)
	buffer = binary.BigEndian.AppendUint32(buffer, operation)
	buffer = binary.BigEndian.AppendUint64(buffer, clientContext)
	buffer = binary.BigEndian.AppendUint32(buffer, 0)
	return buffer
}

func buildMDNSQuery(name string, qtype uint16, qclass uint16) []byte {
	payloadLength := 4 + 4 + len(name) + 1 + 2 + 2
	message := make([]byte, 0, mdnsHeaderLength+payloadLength)
	message = appendMDNSHeader(message, mdnsOpQuery, payloadLength, mdnsQueryContext, mdnsIPCFlagNoErrorSocket)
	message = binary.BigEndian.AppendUint32(message, mdnsFlagShareConnection|mdnsFlagReturnIntermediates|mdnsFlagTimeout)
	message = binary.BigEndian.AppendUint32(message, 0)
	message = append(message, name...)
	message = append(message, 0)
	message = binary.BigEndian.AppendUint16(message, qtype)
	message = binary.BigEndian.AppendUint16(message, qclass)
	return message
}

func readMDNSReply(conn net.Conn) (operation uint32, clientContext uint64, data []byte, err error) {
	var header [mdnsHeaderLength]byte
	if _, err = io.ReadFull(conn, header[:]); err != nil {
		return
	}
	dataLength := binary.BigEndian.Uint32(header[4:8])
	if dataLength > mdnsMaxReplyBytes {
		err = fmt.Errorf("mdns: oversized reply: %d", dataLength)
		return
	}
	operation = binary.BigEndian.Uint32(header[12:16])
	clientContext = binary.BigEndian.Uint64(header[16:24])
	data = make([]byte, dataLength)
	_, err = io.ReadFull(conn, data)
	return
}

type mdnsReply struct {
	flags     uint32
	errorCode int32
	name      string
	rrtype    uint16
	rrclass   uint16
	ttl       uint32
	rdata     []byte
}

func parseMDNSReply(data []byte) (mdnsReply, error) {
	var reply mdnsReply
	reader := mdnsReader{data: data}
	reply.flags = reader.uint32()
	reader.uint32()
	reply.errorCode = int32(reader.uint32())
	reply.name = reader.cString()
	reply.rrtype = reader.uint16()
	reply.rrclass = reader.uint16()
	rdlen := reader.uint16()
	reply.rdata = reader.bytes(int(rdlen))
	reply.ttl = reader.uint32()
	return reply, reader.err
}

func buildMDNSRecord(reply mdnsReply) (D.RR, error) {
	nameBuffer := make([]byte, 256)
	offset, err := D.PackDomainName(D.Fqdn(reply.name), nameBuffer, 0, nil, false)
	if err != nil {
		return nil, err
	}
	record := make([]byte, 0, offset+10+len(reply.rdata))
	record = append(record, nameBuffer[:offset]...)
	record = binary.BigEndian.AppendUint16(record, reply.rrtype)
	record = binary.BigEndian.AppendUint16(record, reply.rrclass)
	record = binary.BigEndian.AppendUint32(record, reply.ttl)
	record = binary.BigEndian.AppendUint16(record, uint16(len(reply.rdata)))
	record = append(record, reply.rdata...)
	resourceRecord, _, err := D.UnpackRR(record, 0)
	if err != nil {
		return nil, err
	}
	return resourceRecord, nil
}

func mdnsError(name string, code int32) error {
	switch code {
	case mdnsErrNoSuchRecord:
		return errMDNSNoSuchRecord
	case mdnsErrNoSuchName:
		return fmt.Errorf("mdns: no such name %s", name)
	case mdnsErrTimeout:
		return fmt.Errorf("mdns: query timeout for %s", name)
	default:
		return fmt.Errorf("mdns: query failed for %s: error %d", name, code)
	}
}

type mdnsReader struct {
	data   []byte
	offset int
	err    error
}

func (r *mdnsReader) uint32() uint32 {
	if r.err != nil || r.offset+4 > len(r.data) {
		r.fail()
		return 0
	}
	value := binary.BigEndian.Uint32(r.data[r.offset:])
	r.offset += 4
	return value
}

func (r *mdnsReader) uint16() uint16 {
	if r.err != nil || r.offset+2 > len(r.data) {
		r.fail()
		return 0
	}
	value := binary.BigEndian.Uint16(r.data[r.offset:])
	r.offset += 2
	return value
}

func (r *mdnsReader) cString() string {
	if r.err != nil {
		return ""
	}
	end := r.offset
	for end < len(r.data) && r.data[end] != 0 {
		end++
	}
	if end >= len(r.data) {
		r.fail()
		return ""
	}
	value := string(r.data[r.offset:end])
	r.offset = end + 1
	return value
}

func (r *mdnsReader) bytes(length int) []byte {
	if r.err != nil || length < 0 || r.offset+length > len(r.data) {
		r.fail()
		return nil
	}
	value := r.data[r.offset : r.offset+length]
	r.offset += length
	return value
}

func (r *mdnsReader) fail() {
	if r.err == nil {
		r.err = errors.New("mdns: truncated reply")
	}
}
