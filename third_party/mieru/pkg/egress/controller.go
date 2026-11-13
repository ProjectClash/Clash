// Copyright (C) 2023  mieru authors
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

package egress

import (
	"context"

	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
)

type Input struct {
	Protocol appctlpb.ProxyProtocol
	Data     []byte
	Env      map[string]string
}

type Action struct {
	Action appctlpb.EgressAction
	Proxy  *appctlpb.EgressProxy
}

type Controller interface {
	FindAction(ctx context.Context, in Input) Action
}

type AlwaysDirectController struct{}

var (
	_ Controller = AlwaysDirectController{}
)

func (c AlwaysDirectController) FindAction(_ context.Context, _ Input) Action {
	return Action{
		Action: appctlpb.EgressAction_DIRECT,
	}
}
