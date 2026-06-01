package rpc

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2021  Seif

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"context"

	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
	"github.com/sudosoc/SUDOSOC-C2/server/core"
	"google.golang.org/protobuf/proto"
)

// Portfwd - Open an in-band port forward
func (s *Server) Portfwd(ctx context.Context, req *sudosocpb.PortfwdReq) (*sudosocpb.Portfwd, error) {
	if req == nil || req.Request == nil {
		return nil, ErrMissingRequestField
	}

	session := core.Sessions.Get(req.Request.SessionID)
	if session == nil {
		return nil, ErrInvalidSessionID
	}
	tunnel := core.Tunnels.Get(req.TunnelID)
	if tunnel == nil {
		return nil, rpcError(core.ErrInvalidTunnelID)
	}
	reqData, err := proto.Marshal(req)
	if err != nil {
		return nil, rpcError(err)
	}
	data, err := session.Request(sudosocpb.MsgNumber(req), s.getTimeout(req), reqData)
	if err != nil {
		return nil, rpcError(err)
	}
	portfwd := &sudosocpb.Portfwd{}
	err = proto.Unmarshal(data, portfwd)
	if err != nil {
		return nil, rpcError(err)
	}
	return portfwd, nil
}
