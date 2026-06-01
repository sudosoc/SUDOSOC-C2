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
	"crypto/sha256"
	"fmt"

	"github.com/sudosoc/SUDOSOC-C2/protobuf/commonpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
	"github.com/sudosoc/SUDOSOC-C2/server/core"
	"github.com/sudosoc/SUDOSOC-C2/server/db"
	"github.com/sudosoc/SUDOSOC-C2/server/db/models"
	"github.com/sudosoc/SUDOSOC-C2/server/log"
	"github.com/sudosoc/SUDOSOC-C2/util/encoders"
)

var (
	fsLog = log.NamedLogger("rcp", "fs")
)

// Ls - List a directory
func (rpc *Server) Ls(ctx context.Context, req *sudosocpb.LsReq) (*sudosocpb.Ls, error) {
	resp := &sudosocpb.Ls{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Mv - Move or rename a file
func (rpc *Server) Mv(ctx context.Context, req *sudosocpb.MvReq) (*sudosocpb.Mv, error) {
	resp := &sudosocpb.Mv{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Cp - Copy a file to another location
func (rpc *Server) Cp(ctx context.Context, req *sudosocpb.CpReq) (*sudosocpb.Cp, error) {
	resp := &sudosocpb.Cp{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Rm - Remove file or directory
func (rpc *Server) Rm(ctx context.Context, req *sudosocpb.RmReq) (*sudosocpb.Rm, error) {
	resp := &sudosocpb.Rm{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Mkdir - Make a directory
func (rpc *Server) Mkdir(ctx context.Context, req *sudosocpb.MkdirReq) (*sudosocpb.Mkdir, error) {
	resp := &sudosocpb.Mkdir{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Cd - Change directory
func (rpc *Server) Cd(ctx context.Context, req *sudosocpb.CdReq) (*sudosocpb.Pwd, error) {
	resp := &sudosocpb.Pwd{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Pwd - Print working directory
func (rpc *Server) Pwd(ctx context.Context, req *sudosocpb.PwdReq) (*sudosocpb.Pwd, error) {
	resp := &sudosocpb.Pwd{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Download - Download a file from the remote file system
func (rpc *Server) Download(ctx context.Context, req *sudosocpb.DownloadReq) (*sudosocpb.Download, error) {
	resp := &sudosocpb.Download{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Upload - Upload a file from the remote file system
func (rpc *Server) Upload(ctx context.Context, req *sudosocpb.UploadReq) (*sudosocpb.Upload, error) {
	resp := &sudosocpb.Upload{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	if req.IsIOC {
		go trackIOC(req, resp)
	}
	return resp, nil
}

// Chmod - Change permission on a file or directory
func (rpc *Server) Chmod(ctx context.Context, req *sudosocpb.ChmodReq) (*sudosocpb.Chmod, error) {
	resp := &sudosocpb.Chmod{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Chown - Change owner on a file or directory
func (rpc *Server) Chown(ctx context.Context, req *sudosocpb.ChownReq) (*sudosocpb.Chown, error) {
	resp := &sudosocpb.Chown{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Chtimes - Change file access and modification times on a file or directory
func (rpc *Server) Chtimes(ctx context.Context, req *sudosocpb.ChtimesReq) (*sudosocpb.Chtimes, error) {
	resp := &sudosocpb.Chtimes{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// MemfilesList - List memfiles
func (rpc *Server) MemfilesList(ctx context.Context, req *sudosocpb.MemfilesListReq) (*sudosocpb.Ls, error) {
	resp := &sudosocpb.Ls{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// MemfilesAdd - Add memfile
func (rpc *Server) MemfilesAdd(ctx context.Context, req *sudosocpb.MemfilesAddReq) (*sudosocpb.MemfilesAdd, error) {
	resp := &sudosocpb.MemfilesAdd{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// MemfilesRm - Close memfile
func (rpc *Server) MemfilesRm(ctx context.Context, req *sudosocpb.MemfilesRmReq) (*sudosocpb.MemfilesRm, error) {
	resp := &sudosocpb.MemfilesRm{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func hashUploadData(encoder string, data []byte) [32]byte {
	if encoder == "gzip" {
		decodedData, err := new(encoders.Gzip).Decode(data)
		if err != nil {
			return sha256.Sum256(nil)
		}
		return sha256.Sum256(decodedData)
	} else {
		return sha256.Sum256(data)
	}
}

func trackIOC(req *sudosocpb.UploadReq, resp *sudosocpb.Upload) {
	fsLog.Debugf("Adding IOC to database ...")
	request := req.GetRequest()
	if request == nil {
		fsLog.Error("No request for upload")
		return
	}
	session := core.Sessions.Get(request.SessionID)
	if session == nil {
		fsLog.Error("No session for upload request")
		return
	}
	host, err := db.HostByHostUUID(session.UUID)
	if err != nil {
		fsLog.Errorf("No host for session uuid %v", session.UUID)
		return
	}

	sum := hashUploadData(req.Encoder, req.Data)
	ioc := &models.IOC{
		HostID:   host.HostUUID,
		Path:     resp.Path,
		FileHash: fmt.Sprintf("%x", sum),
	}
	if db.Session().Create(ioc).Error != nil {
		fsLog.Error("Failed to create IOC")
	}
}

// Grep - Search a file or directory for text matching a regex
func (rpc *Server) Grep(ctx context.Context, req *sudosocpb.GrepReq) (*sudosocpb.Grep, error) {
	resp := &sudosocpb.Grep{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Mount - Get information on mounted filesystems
func (rpc *Server) Mount(ctx context.Context, req *sudosocpb.MountReq) (*sudosocpb.Mount, error) {
	resp := &sudosocpb.Mount{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
