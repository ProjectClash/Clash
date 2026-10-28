package clash

import (
	"strings"
	"unicode/utf8"
)

func bridgeSafeString(value string) string {
	if utf8.ValidString(value) {
		return value
	}
	return strings.ToValidUTF8(value, "�")
}

type bridgeSafePlatformDecorator struct{ PlatformInterface }

func (p bridgeSafePlatformDecorator) WriteLog(message string) {
	p.PlatformInterface.WriteLog(bridgeSafeString(message))
}

func (p bridgeSafePlatformDecorator) TunFailed(reason string) {
	p.PlatformInterface.TunFailed(bridgeSafeString(reason))
}

func bridgeSafePlatform(platform PlatformInterface) PlatformInterface {
	if platform == nil {
		return nil
	}
	if _, ok := platform.(bridgeSafePlatformDecorator); ok {
		return platform
	}
	return bridgeSafePlatformDecorator{platform}
}

type bridgeSafeClashHandlerDecorator struct{ APIClientHandler }

func (h bridgeSafeClashHandlerDecorator) Disconnected(message string) {
	h.APIClientHandler.Disconnected(bridgeSafeString(message))
}

func (h bridgeSafeClashHandlerDecorator) WriteTraffic(message string) {
	h.APIClientHandler.WriteTraffic(bridgeSafeString(message))
}

func (h bridgeSafeClashHandlerDecorator) WriteMemory(message string) {
	h.APIClientHandler.WriteMemory(bridgeSafeString(message))
}

func (h bridgeSafeClashHandlerDecorator) WriteLogs(message string) {
	h.APIClientHandler.WriteLogs(bridgeSafeString(message))
}

func (h bridgeSafeClashHandlerDecorator) WriteConnections(message string) {
	h.APIClientHandler.WriteConnections(bridgeSafeString(message))
}

func (h bridgeSafeClashHandlerDecorator) WriteMode(message string) {
	h.APIClientHandler.WriteMode(bridgeSafeString(message))
}

func bridgeSafeClashHandler(handler APIClientHandler) APIClientHandler {
	if handler == nil {
		return nil
	}
	if _, ok := handler.(bridgeSafeClashHandlerDecorator); ok {
		return handler
	}
	return bridgeSafeClashHandlerDecorator{handler}
}

type bridgeSafeSTUNHandlerDecorator struct{ STUNTestHandler }

func (h bridgeSafeSTUNHandlerDecorator) OnError(message string) {
	h.STUNTestHandler.OnError(bridgeSafeString(message))
}

func bridgeSafeSTUNHandler(handler STUNTestHandler) STUNTestHandler {
	if handler == nil {
		return nil
	}
	if _, ok := handler.(bridgeSafeSTUNHandlerDecorator); ok {
		return handler
	}
	return bridgeSafeSTUNHandlerDecorator{handler}
}

type bridgeSafeNQHandlerDecorator struct{ NetworkQualityTestHandler }

func (h bridgeSafeNQHandlerDecorator) OnError(message string) {
	h.NetworkQualityTestHandler.OnError(bridgeSafeString(message))
}

func bridgeSafeNQHandler(handler NetworkQualityTestHandler) NetworkQualityTestHandler {
	if handler == nil {
		return nil
	}
	if _, ok := handler.(bridgeSafeNQHandlerDecorator); ok {
		return handler
	}
	return bridgeSafeNQHandlerDecorator{handler}
}

type bridgeSafeConnectionEventsDecorator struct{ ConnectionEventsWriter }

func (w bridgeSafeConnectionEventsDecorator) WriteConnectionEvents(message string) {
	w.ConnectionEventsWriter.WriteConnectionEvents(bridgeSafeString(message))
}

func bridgeSafeConnectionEvents(writer ConnectionEventsWriter) ConnectionEventsWriter {
	if _, ok := writer.(bridgeSafeConnectionEventsDecorator); ok {
		return writer
	}
	return bridgeSafeConnectionEventsDecorator{writer}
}

type bridgeSafeLogBatchDecorator struct{ LogBatchWriter }

func (w bridgeSafeLogBatchDecorator) WriteLogBatch(linesJSON string) {
	w.LogBatchWriter.WriteLogBatch(bridgeSafeString(linesJSON))
}

func bridgeSafeLogBatch(writer LogBatchWriter) LogBatchWriter {
	if writer == nil {
		return nil
	}
	if _, ok := writer.(bridgeSafeLogBatchDecorator); ok {
		return writer
	}
	return bridgeSafeLogBatchDecorator{writer}
}

type bridgeSafeRuleNotificationDecorator struct{ RuleNotificationHandler }

func (h bridgeSafeRuleNotificationDecorator) RuleMatched(text string, rule string) {
	h.RuleNotificationHandler.RuleMatched(bridgeSafeString(text), bridgeSafeString(rule))
}
