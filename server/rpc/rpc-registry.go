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

	"github.com/sudosoc/SUDOSOC-C2/protobuf/commonpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
)

// RegistryRead - gRPC interface to read a registry key from a session
func (rpc *Server) RegistryRead(ctx context.Context, req *sudosocpb.RegistryReadReq) (*sudosocpb.RegistryRead, error) {
	resp := &sudosocpb.RegistryRead{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// RegistryWrite - gRPC interface to write to a registry key on a session
func (rpc *Server) RegistryWrite(ctx context.Context, req *sudosocpb.RegistryWriteReq) (*sudosocpb.RegistryWrite, error) {
	resp := &sudosocpb.RegistryWrite{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// RegistryCreateKey - gRPC interface to create a registry key on a session
func (rpc *Server) RegistryCreateKey(ctx context.Context, req *sudosocpb.RegistryCreateKeyReq) (*sudosocpb.RegistryCreateKey, error) {
	resp := &sudosocpb.RegistryCreateKey{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// RegistryDeleteKey - gRPC interface to delete a registry key on a session
func (rpc *Server) RegistryDeleteKey(ctx context.Context, req *sudosocpb.RegistryDeleteKeyReq) (*sudosocpb.RegistryDeleteKey, error) {
	resp := &sudosocpb.RegistryDeleteKey{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// RegistryListSubKeys - gRPC interface to list the sub keys of a registry key
func (rpc *Server) RegistryListSubKeys(ctx context.Context, req *sudosocpb.RegistrySubKeyListReq) (*sudosocpb.RegistrySubKeyList, error) {
	resp := &sudosocpb.RegistrySubKeyList{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// RegistryListSubKeys - gRPC interface to list the sub keys of a registry key
func (rpc *Server) RegistryListValues(ctx context.Context, req *sudosocpb.RegistryListValuesReq) (*sudosocpb.RegistryValuesList, error) {
	resp := &sudosocpb.RegistryValuesList{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// RegistryDumpHive - gRPC interface to dump a specific registry hive as a binary file
func (rpc *Server) RegistryReadHive(ctx context.Context, req *sudosocpb.RegistryReadHiveReq) (*sudosocpb.RegistryReadHive, error) {
	resp := &sudosocpb.RegistryReadHive{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
