package rpc

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2022  Seif

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
	"strings"
	"time"

	"github.com/sudosoc/SUDOSOC-C2/protobuf/commonpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
	"github.com/sudosoc/SUDOSOC-C2/server/core"
	"github.com/sudosoc/SUDOSOC-C2/server/db"
	"github.com/sudosoc/SUDOSOC-C2/server/db/models"
	"google.golang.org/protobuf/proto"
)

// Kill - Kill the implant process
func (rpc *Server) Kill(ctx context.Context, kill *sudosocpb.KillReq) (*commonpb.Empty, error) {
	var (
		beacon *models.Beacon
		err    error
	)

	if kill == nil || kill.Request == nil {
		return &commonpb.Empty{}, ErrMissingRequestField
	}

	session := core.Sessions.Get(kill.Request.SessionID)
	if session == nil {
		beacon, err = db.BeaconByID(kill.Request.BeaconID)
		if err != nil {
			return &commonpb.Empty{}, ErrInvalidBeaconID
		} else {
			return rpc.killBeacon(kill, beacon)
		}
	}
	return rpc.killSession(kill, session)
}

func (rpc *Server) killSession(kill *sudosocpb.KillReq, session *core.Session) (*commonpb.Empty, error) {
	data, err := proto.Marshal(kill)
	if err != nil {
		return nil, rpcError(err)
	}
	timeout := time.Duration(kill.Request.GetTimeout())
	// Do not block waiting for the msg send, the implant connection may already be dead
	go session.Request(sudosocpb.MsgNumber(kill), timeout, data)
	core.Sessions.Remove(session.ID)
	return &commonpb.Empty{}, nil
}

func (rpc *Server) killBeacon(kill *sudosocpb.KillReq, beacon *models.Beacon) (*commonpb.Empty, error) {
	resp := &commonpb.Empty{}
	request := kill.GetRequest()
	request.SessionID = ""
	request.Async = true
	request.BeaconID = beacon.ID.String()
	reqData, err := proto.Marshal(request)
	if err != nil {
		return nil, rpcError(err)
	}
	task, err := beacon.Task(&sudosocpb.Envelope{
		Type: sudosocpb.MsgKillSessionReq,
		Data: reqData,
	})
	if err != nil {
		return nil, rpcError(err)
	}
	parts := strings.Split(string(kill.ProtoReflect().Descriptor().FullName().Name()), ".")
	name := parts[len(parts)-1]
	task.Description = name
	// Update db
	err = db.Session().Save(task).Error
	if err != nil {
		return nil, rpcError(err)
	}
	return resp, nil
}
