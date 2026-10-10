package route

import (
	"net"

	"github.com/metacubex/http"
)

func UpgradeWebSocket(request *http.Request, writer http.ResponseWriter) (net.Conn, error) {
	conn, _, err := wsUpgrade(request, writer)
	return conn, err
}

func WriteWebSocketText(conn net.Conn, payload []byte) error {
	return wsWriteServerText(conn, payload)
}
