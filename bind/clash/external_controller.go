package clash

import (
	"sync/atomic"

	"github.com/ProjectClash/Clash/config"
	"github.com/ProjectClash/Clash/hub/route"
	"github.com/ProjectClash/Clash/log"
)

var userControllerLive atomic.Bool

func controllerServerConfig(cfg *config.Config, bindingSocketPath string) *route.Config {
	return mergeRemoteControl(configurationControllerConfig(cfg, bindingSocketPath), currentRemoteControlSettings(), currentRuntimeProfile())
}

func configurationControllerConfig(cfg *config.Config, bindingSocketPath string) *route.Config {
	server := &route.Config{UnixAddr: bindingSocketPath}
	if cfg == nil || cfg.Controller == nil {
		return server
	}
	controller := cfg.Controller
	server.Addr = controller.ExternalController
	server.TLSAddr = controller.ExternalControllerTLS
	server.Secret = controller.Secret
	server.DohServer = controller.ExternalDohServer
	if cfg.TLS != nil {
		server.Certificate = cfg.TLS.Certificate
		server.PrivateKey = cfg.TLS.PrivateKey
		server.ClientAuthType = cfg.TLS.ClientAuthType
		server.ClientAuthCert = cfg.TLS.ClientAuthCert
		server.EchKey = cfg.TLS.EchKey
	}
	server.IsDebug = cfg.General.LogLevel == log.DEBUG
	memoryProfilingForDebug(server.IsDebug)
	server.Cors = route.Cors{
		AllowOrigins:        controller.Cors.AllowOrigins,
		AllowPrivateNetwork: controller.Cors.AllowPrivateNetwork,
	}
	return server
}

func recreateControlPlane(cfg *config.Config, bindingSocketPath string) *route.Config {
	remoteControl.tx.Lock()
	defer remoteControl.tx.Unlock()
	return recreateControlPlaneLocked(cfg, bindingSocketPath)
}

func recreateControlPlaneLocked(cfg *config.Config, bindingSocketPath string) *route.Config {
	if cfg != nil && cfg.Controller != nil && cfg.Controller.ExternalUI != "" {
		route.SetUIPath(cfg.Controller.ExternalUI)
	}
	server := controllerServerConfig(cfg, bindingSocketPath)
	route.ReCreateServer(server)
	userControllerLive.Store(server.Addr != "" || server.TLSAddr != "")
	remoteControl.mu.Lock()
	remoteControl.base = configurationControllerConfig(cfg, bindingSocketPath)
	remoteControl.applied = remoteControl.settings
	remoteControl.mu.Unlock()
	return server
}

func applyExternalController(cfg *config.Config) {
	path := setupClashAPIPath
	if path == "" {
		return
	}
	socket := bindingSocketPathFor(path)
	if len([]byte(socket)) > clashAPIMaxUnixPathBytes {
		log.Errorln("[iOS] Clash API Unix path is %d bytes; Darwin limit is %d: %s",
			len([]byte(socket)), clashAPIMaxUnixPathBytes, socket)
	}
	server, skipped := reconcileControlPlane(cfg, socket)
	if skipped {
		return
	}
	if server.Addr == "" && server.TLSAddr == "" {
		log.Infoln("[Apple] external-controller removed from the configuration: closed")
	} else {
		log.Infoln("[Apple] external-controller listening as configured: addr=%q tls=%q", server.Addr, server.TLSAddr)
	}
	if socket == "" {
		return
	}
	if err := secureBindingControlSocket(socket); err != nil {
		log.Errorln("[iOS] %v", err)
	}
}

func reconcileControlPlane(cfg *config.Config, socket string) (server *route.Config, skipped bool) {
	remoteControl.tx.Lock()
	defer remoteControl.tx.Unlock()
	if probe := controllerServerConfig(cfg, socket); probe.Addr == "" && probe.TLSAddr == "" &&
		!userControllerLive.Load() {
		remoteControl.mu.Lock()
		remoteControl.base = configurationControllerConfig(cfg, socket)
		remoteControl.mu.Unlock()
		return nil, true
	}
	return recreateControlPlaneLocked(cfg, socket), false
}
