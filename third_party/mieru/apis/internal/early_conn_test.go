// Copyright (C) 2025  mieru authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package internal_test

import (
	"io"
	"sync"
	"testing"

	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/apis/internal"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/internal/testtool"
)

func TestEarlyConnRequest(t *testing.T) {
	clientConn, serverConn := testtool.BufPipe()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		defer serverConn.Close()

		var req model.Request
		if err := req.ReadFromSocks5(serverConn); err != nil {
			t.Errorf("server: failed to read request: %v", err)
			return
		}

		reply := []byte{constant.Socks5Version, 0, 0, constant.Socks5IPv4Address, 0, 0, 0, 0, 0, 0}
		if _, err := serverConn.Write(reply); err != nil {
			t.Errorf("server: failed to write reply: %v", err)
			return
		}

		ping := make([]byte, 4)
		if _, err := io.ReadFull(serverConn, ping); err != nil {
			t.Errorf("server: failed to read data: %v", err)
			return
		}
		if string(ping) != "ping" {
			t.Errorf("server: expected client to send 'ping', got '%s'", string(ping))
			return
		}

		if _, err := serverConn.Write([]byte("pong")); err != nil {
			t.Errorf("server: failed to write data: %v", err)
			return
		}
	}()

	req := &model.Request{
		Command: constant.Socks5ConnectCmd,
		DstAddr: model.AddrSpec{
			FQDN: "example.com",
			Port: 80,
		},
	}
	conn := internal.NewEarlyConn(clientConn)
	conn.SetRequest(req)
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("client: failed to write data: %v", err)
	}

	pong := make([]byte, 4)
	if _, err := io.ReadFull(conn, pong); err != nil {
		t.Fatalf("client: failed to read data: %v", err)
	}

	if string(pong) != "pong" {
		t.Fatalf("client: expected server to send 'pong', got '%s'", string(pong))
	}

	wg.Wait()
}
