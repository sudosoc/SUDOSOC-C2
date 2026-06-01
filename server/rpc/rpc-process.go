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

	"github.com/sudosoc/SUDOSOC-C2/protobuf/commonpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
)

// Ps - List the processes on the remote machine
func (rpc *Server) Ps(ctx context.Context, req *sudosocpb.PsReq) (*sudosocpb.Ps, error) {
	resp := &sudosocpb.Ps{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// ProcessDump - Dump the memory of a remote process
func (rpc *Server) ProcessDump(ctx context.Context, req *sudosocpb.ProcessDumpReq) (*sudosocpb.ProcessDump, error) {
	resp := &sudosocpb.ProcessDump{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Terminate - Terminate a remote process
func (rpc *Server) Terminate(ctx context.Context, req *sudosocpb.TerminateReq) (*sudosocpb.Terminate, error) {
	resp := &sudosocpb.Terminate{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
