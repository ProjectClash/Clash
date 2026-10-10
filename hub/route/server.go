package route

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ProjectClash/Clash/adapter/inbound"
	"github.com/ProjectClash/Clash/common/utils"
	"github.com/ProjectClash/Clash/component/ca"
	"github.com/ProjectClash/Clash/component/ech"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
	"github.com/ProjectClash/Clash/ntp"
	"github.com/ProjectClash/Clash/tunnel/statistic"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/cors"
	"github.com/metacubex/chi/middleware"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

var (
	uiPath = ""

	httpServer *http.Server
	tlsServer  *http.Server
	unixServer *http.Server
	pipeServer *http.Server

	httpListener net.Listener
	tlsListener  net.Listener
	unixListener net.Listener
	pipeListener net.Listener
	serverMu     sync.Mutex

	embedMode = false
)

func SetEmbedMode(embed bool) {
	embedMode = embed
}

//
//
var geoUpdaterAllowed = false

func SetGeoUpdaterAllowed(allowed bool) {
	geoUpdaterAllowed = allowed
}

type Traffic struct {
	Up        int64 `json:"up"`
	Down      int64 `json:"down"`
	UpTotal   int64 `json:"upTotal"`
	DownTotal int64 `json:"downTotal"`
}

type Memory struct {
	Inuse     uint64 `json:"inuse"`
	OSLimit   uint64 `json:"oslimit"` // maybe we need it in the future
	Footprint *int64 `json:"footprint,omitempty"`
}

var memoryFootprintMu sync.RWMutex
var memoryFootprintReader func() int64

func SetMemoryFootprintReader(reader func() int64) {
	memoryFootprintMu.Lock()
	memoryFootprintReader = reader
	memoryFootprintMu.Unlock()
}

func currentMemoryFootprint() *int64 {
	memoryFootprintMu.RLock()
	reader := memoryFootprintReader
	memoryFootprintMu.RUnlock()
	if reader == nil {
		return nil
	}
	value := reader()
	if value < 0 {
		value = 0
	}
	return &value
}

type Config struct {
	Addr           string
	TLSAddr        string
	UnixAddr       string
	PipeAddr       string
	RoutingMark    int
	Secret         string
	Certificate    string
	PrivateKey     string
	ClientAuthType string
	ClientAuthCert string
	EchKey         string
	DohServer      string
	IsDebug        bool
	Cors           Cors

	Managed      bool
	AcceptFilter func(net.Addr) bool
}

type Cors struct {
	AllowOrigins        []string
	AllowPrivateNetwork bool
}

func (c Cors) Apply(r chi.Router) {
	r.Use(cors.New(cors.Options{
		AllowedOrigins:      c.AllowOrigins,
		AllowedMethods:      []string{"GET", "POST", "PUT", "PATCH", "DELETE"},
		AllowedHeaders:      []string{"Content-Type", "Authorization"},
		AllowPrivateNetwork: c.AllowPrivateNetwork,
		MaxAge:              300,
	}).Handler)
}

func ReCreateServer(cfg *Config) {
	serverMu.Lock()
	defer serverMu.Unlock()
	start(cfg)
	startTLS(cfg)
	startUnix(cfg)
	if inbound.SupportNamedPipe {
		startPipe(cfg)
	}
}

func SetUIPath(path string) {
	uiPath = C.Path.Resolve(path)
}

func router(isDebug bool, secret string, dohServer string, cors Cors) *chi.Mux {
	return routerServingUI(isDebug, secret, dohServer, cors, true)
}

func routerServingUI(isDebug bool, secret string, dohServer string, cors Cors, serveUI bool) *chi.Mux {
	r := chi.NewRouter()
	r.Use(closeHijackedOnReturn)
	cors.Apply(r)
	r.Group(func(r chi.Router) {
		if secret != "" {
			r.Use(authentication(secret))
		}
		if isDebug {
			r.Mount("/debug", func() http.Handler {
				r := chi.NewRouter()
				r.Put("/gc", func(w http.ResponseWriter, r *http.Request) {
					debug.FreeOSMemory()
				})
				handler := middleware.Profiler
				r.Mount("/", handler())
				return r
			}())
		}
		r.Get("/", hello)
		r.Get("/logs", getLogs)
		r.Get("/traffic", traffic)
		r.Get("/memory", memory)
		r.Get("/version", version)
		r.Mount("/configs", configRouter())
		r.Mount("/proxies", proxyRouter())
		r.Mount("/group", groupRouter())
		r.Mount("/rules", ruleRouter())
		r.Mount("/connections", connectionRouter())
		r.Mount("/providers/proxies", proxyProviderRouter())
		r.Mount("/providers/rules", ruleProviderRouter())
		r.Mount("/cache", cacheRouter())
		r.Mount("/dns", dnsRouter())
		r.Mount("/storage", storageRouter())
		if !embedMode { // disallow restart in embed mode
			r.Mount("/restart", restartRouter())
		}
		r.Mount("/upgrade", upgradeRouter())
		addExternalRouters(r)

	})

	if uiPath != "" && serveUI {
		r.Group(func(r chi.Router) {
			uiFS := http.FileSystem(http.Dir(uiPath))
			if embedMode {
				uiFS = clashUserspaceFileSystem{uiFS}
			}
			fs := http.StripPrefix("/ui", http.FileServer(uiFS))
			r.Get("/ui", http.RedirectHandler("/ui/", http.StatusTemporaryRedirect).ServeHTTP)
			r.Get("/ui/*", func(w http.ResponseWriter, r *http.Request) {
				fs.ServeHTTP(w, r)
			})
		})
	}
	if len(dohServer) > 0 && dohServer[0] == '/' {
		r.Mount(dohServer, dohRouter())
	}

	return r
}

func start(cfg *Config) {
	// first stop existing server
	if httpListener != nil {
		_ = httpListener.Close()
		httpListener = nil
	}
	if httpServer != nil {
		_ = httpServer.Close()
		httpServer = nil
	}

	recordHTTPStatus(ListenerStatus{Address: cfg.Addr})
	// handle addr
	if len(cfg.Addr) > 0 {
		lc := inbound.NewListenConfig()
		lc.SetRouteMark(cfg.RoutingMark)
		l, err := lc.Listen(context.Background(), "tcp", cfg.Addr)
		if err != nil {
			log.Errorln("External controller listen error: %s", err)
			recordHTTPStatus(ListenerStatus{Address: cfg.Addr, Err: err})
			return
		}
		log.Infoln("RESTful API listening at: %s", l.Addr().String())
		recordHTTPStatus(ListenerStatus{Address: l.Addr().String()})
		l = wrapNetworkListener(l, cfg)

		server := &http.Server{
			Handler:     routerServingUI(cfg.IsDebug, cfg.Secret, cfg.DohServer, cfg.Cors, !cfg.Managed),
			ConnContext: networkConnContext(cfg.Managed),
		}
		httpServer = server
		httpListener = l
		go func() {
			if serveErr := server.Serve(l); serveErr != nil {
				log.Errorln("External controller serve error: %s", serveErr)
			}
		}()
	}
}

func startTLS(cfg *Config) {
	// first stop existing server
	if tlsListener != nil {
		_ = tlsListener.Close()
		tlsListener = nil
	}
	if tlsServer != nil {
		_ = tlsServer.Close()
		tlsServer = nil
	}

	recordTLSStatus(ListenerStatus{Address: cfg.TLSAddr})
	// handle tlsAddr
	if len(cfg.TLSAddr) > 0 {
		certLoader, err := ca.NewTLSKeyPairLoader(cfg.Certificate, cfg.PrivateKey)
		if err != nil {
			log.Errorln("External controller tls listen error: %s", err)
			recordTLSStatus(ListenerStatus{Address: cfg.TLSAddr, Err: err})
			return
		}

		lc := inbound.NewListenConfig()
		lc.SetRouteMark(cfg.RoutingMark)
		l, err := lc.Listen(context.Background(), "tcp", cfg.TLSAddr)
		if err != nil {
			log.Errorln("External controller tls listen error: %s", err)
			recordTLSStatus(ListenerStatus{Address: cfg.TLSAddr, Err: err})
			return
		}

		log.Infoln("RESTful API tls listening at: %s", l.Addr().String())
		boundAddress := l.Addr().String()
		l = wrapNetworkListener(l, cfg)
		tlsConfig := &tls.Config{Time: ntp.Now}
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}
		tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return certLoader()
		}
		tlsConfig.ClientAuth = ca.ClientAuthTypeFromString(cfg.ClientAuthType)
		if len(cfg.ClientAuthCert) > 0 {
			if tlsConfig.ClientAuth == tls.NoClientCert {
				tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			}
		}
		if tlsConfig.ClientAuth == tls.VerifyClientCertIfGiven || tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert {
			pool, err := ca.LoadCertificates(cfg.ClientAuthCert)
			if err != nil {
				log.Errorln("External controller tls listen error: %s", err)
				_ = l.Close()
				recordTLSStatus(ListenerStatus{Address: cfg.TLSAddr, Err: err})
				return
			}
			tlsConfig.ClientCAs = pool
		}

		if cfg.EchKey != "" {
			err = ech.LoadECHKey(cfg.EchKey, tlsConfig)
			if err != nil {
				log.Errorln("External controller tls serve error: %s", err)
				_ = l.Close()
				recordTLSStatus(ListenerStatus{Address: cfg.TLSAddr, Err: err})
				return
			}
		}
		recordTLSStatus(ListenerStatus{Address: boundAddress})
		server := &http.Server{
			Handler:     routerServingUI(cfg.IsDebug, cfg.Secret, cfg.DohServer, cfg.Cors, !cfg.Managed),
			ConnContext: networkConnContext(cfg.Managed),
		}
		tlsServer = server
		tlsListener = tls.NewListener(l, tlsConfig)
		listener := tlsListener
		go func() {
			if serveErr := server.Serve(listener); serveErr != nil {
				log.Errorln("External controller tls serve error: %s", serveErr)
			}
		}()
	}
}

func startUnix(cfg *Config) {
	if keepUnixListener(cfg) {
		return
	}
	// first stop existing server
	if unixListener != nil {
		_ = unixListener.Close()
		unixListener = nil
	}
	if unixServer != nil {
		_ = unixServer.Close()
		unixServer = nil
	}

	// handle addr
	if len(cfg.UnixAddr) > 0 {
		addr := C.Path.Resolve(cfg.UnixAddr)

		dir := filepath.Dir(addr)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				log.Errorln("External controller unix listen error: %s", err)
				return
			}
		}

		// https://devblogs.microsoft.com/commandline/af_unix-comes-to-windows/
		//
		// Note: As mentioned above in the ‘security’ section, when a socket binds a socket to a valid pathname address,
		// a socket file is created within the filesystem. On Linux, the application is expected to unlink
		// (see the notes section in the man page for AF_UNIX) before any other socket can be bound to the same address.
		// The same applies to Windows unix sockets, except that, DeleteFile (or any other file delete API)
		// should be used to delete the socket file prior to calling bind with the same path.
		_ = syscall.Unlink(addr)

		lc := inbound.NewListenConfig()
		lc.SetRouteMark(0) // don't set route mark for unix socket
		l, err := lc.Listen(context.Background(), "unix", addr)
		if err != nil {
			log.Errorln("External controller unix listen error: %s", err)
			return
		}
		_ = os.Chmod(addr, 0o666)
		log.Infoln("RESTful API unix listening at: %s", l.Addr().String())

		unixHandler = newSwappableHandler(router(cfg.IsDebug, "", cfg.DohServer, cfg.Cors))
		server := &http.Server{
			Handler: unixHandler,
		}
		unixServer = server
		unixListener = l
		unixAddress = addr
		unixSocketFile, _ = os.Lstat(addr)
		serving := new(atomic.Bool)
		serving.Store(true)
		unixServing = serving
		go func() {
			if serveErr := server.Serve(l); serveErr != nil {
				log.Errorln("External controller unix serve error: %s", serveErr)
			}
			serving.Store(false)
		}()
	}
}

func startPipe(cfg *Config) {
	// first stop existing server
	if pipeListener != nil {
		_ = pipeListener.Close()
		pipeListener = nil
	}
	if pipeServer != nil {
		_ = pipeServer.Close()
		pipeServer = nil
	}

	// handle addr
	if len(cfg.PipeAddr) > 0 {
		if !strings.HasPrefix(cfg.PipeAddr, "\\\\.\\pipe\\") { // windows namedpipe must start with "\\.\pipe\"
			log.Errorln("External controller pipe listen error: windows namedpipe must start with \"\\\\.\\pipe\\\"")
			return
		}

		l, err := inbound.ListenNamedPipe(cfg.PipeAddr)
		if err != nil {
			log.Errorln("External controller pipe listen error: %s", err)
			return
		}
		log.Infoln("RESTful API pipe listening at: %s", l.Addr().String())

		server := &http.Server{
			Handler: router(cfg.IsDebug, "", cfg.DohServer, cfg.Cors),
		}
		pipeServer = server
		pipeListener = l
		go func() {
			if serveErr := server.Serve(l); serveErr != nil {
				log.Errorln("External controller pipe serve error: %s", serveErr)
			}
		}()
	}
}

func safeEqual(a, b string) bool {
	aBuf := utils.ImmutableBytesFromString(a)
	bBuf := utils.ImmutableBytesFromString(b)
	return subtle.ConstantTimeCompare(aBuf, bBuf) == 1
}

func authentication(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			// Browser websocket not support custom header
			if r.Header.Get("Upgrade") == "websocket" && r.URL.Query().Get("token") != "" {
				token := r.URL.Query().Get("token")
				if !safeEqual(token, secret) {
					render.Status(r, http.StatusUnauthorized)
					render.JSON(w, r, ErrUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			header := r.Header.Get("Authorization")
			bearer, token, found := strings.Cut(header, " ")

			hasInvalidHeader := bearer != "Bearer"
			hasInvalidSecret := !found || !safeEqual(token, secret)
			if hasInvalidHeader || hasInvalidSecret {
				render.Status(r, http.StatusUnauthorized)
				render.JSON(w, r, ErrUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}

func hello(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{"hello": "mihomo"})
}

func traffic(w http.ResponseWriter, r *http.Request) {
	var wsConn net.Conn
	if r.Header.Get("Upgrade") == "websocket" {
		var err error
		wsConn, _, err = wsUpgrade(r, w)
		if err != nil {
			return
		}
	}

	if wsConn == nil {
		w.Header().Set("Content-Type", "application/json")
		render.Status(r, http.StatusOK)
	}

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	t := statistic.DefaultManager
	onlyProxy := r.URL.Query().Get("only-proxy") == "true"
	buf := &bytes.Buffer{}
	var err error
	for range tick.C {
		buf.Reset()
		up, down := t.NowTraffic(onlyProxy)
		upTotal, downTotal := t.TotalTraffic(onlyProxy)
		if err := json.NewEncoder(buf).Encode(Traffic{
			Up:        up,
			Down:      down,
			UpTotal:   upTotal,
			DownTotal: downTotal,
		}); err != nil {
			break
		}

		if wsConn == nil {
			_, err = w.Write(buf.Bytes())
			w.(http.Flusher).Flush()
		} else {
			err = wsWriteServerText(wsConn, buf.Bytes())
		}

		if err != nil {
			break
		}
	}
}

func memory(w http.ResponseWriter, r *http.Request) {
	var wsConn net.Conn
	if r.Header.Get("Upgrade") == "websocket" {
		var err error
		wsConn, _, err = wsUpgrade(r, w)
		if err != nil {
			return
		}
	}

	if wsConn == nil {
		w.Header().Set("Content-Type", "application/json")
		render.Status(r, http.StatusOK)
	}

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	t := statistic.DefaultManager
	buf := &bytes.Buffer{}
	var err error
	first := true
	for range tick.C {
		buf.Reset()

		inuse := t.Memory()
		// make chat.js begin with zero
		// this is shit var,but we need output 0 for first time
		if first {
			inuse = 0
			first = false
		}
		if err := json.NewEncoder(buf).Encode(Memory{
			Inuse:     inuse,
			OSLimit:   0,
			Footprint: currentMemoryFootprint(),
		}); err != nil {
			break
		}
		if wsConn == nil {
			_, err = w.Write(buf.Bytes())
			w.(http.Flusher).Flush()
		} else {
			err = wsWriteServerText(wsConn, buf.Bytes())
		}

		if err != nil {
			break
		}
	}
}

type Log struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
}
type LogStructuredField struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
type LogStructured struct {
	Time    string               `json:"time"`
	Level   string               `json:"level"`
	Message string               `json:"message"`
	Fields  []LogStructuredField `json:"fields"`
}

func getLogs(w http.ResponseWriter, r *http.Request) {
	levelText := r.URL.Query().Get("level")
	if levelText == "" {
		levelText = "info"
	}

	formatText := r.URL.Query().Get("format")
	isStructured := false
	if formatText == "structured" {
		isStructured = true
	}

	level, ok := log.LogLevelMapping[levelText]
	if !ok {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	var wsConn net.Conn
	if r.Header.Get("Upgrade") == "websocket" {
		var err error
		wsConn, _, err = wsUpgrade(r, w)
		if err != nil {
			return
		}
	}

	if wsConn == nil {
		w.Header().Set("Content-Type", "application/json")
		render.Status(r, http.StatusOK)
	}

	ch := make(chan log.Event, 1024)
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)
	buf := &bytes.Buffer{}

	go func() {
		for logM := range sub {
			select {
			case ch <- logM:
			default:
			}
		}
		close(ch)
	}()

	for logM := range ch {
		if logM.LogLevel < level {
			continue
		}
		buf.Reset()

		if !isStructured {
			if err := json.NewEncoder(buf).Encode(Log{
				Type:    logM.Type(),
				Payload: logM.Payload,
			}); err != nil {
				break
			}
		} else {
			newLevel := logM.Type()
			if newLevel == "warning" {
				newLevel = "warn"
			}
			if err := json.NewEncoder(buf).Encode(LogStructured{
				Time:    time.Now().Format(time.TimeOnly),
				Level:   newLevel,
				Message: logM.Payload,
				Fields:  []LogStructuredField{},
			}); err != nil {
				break
			}
		}

		var err error
		if wsConn == nil {
			_, err = w.Write(buf.Bytes())
			w.(http.Flusher).Flush()
		} else {
			err = wsWriteServerText(wsConn, buf.Bytes())
		}

		if err != nil {
			break
		}
	}
}

func version(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{"meta": C.Meta, "version": C.Version})
}
