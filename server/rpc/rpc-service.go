package rpc

import (
	"context"

	"github.com/sudosoc/SUDOSOC-C2/protobuf/commonpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
)

// Services - List and control services
func (rpc *Server) Services(ctx context.Context, req *sudosocpb.ServicesReq) (*sudosocpb.Services, error) {
	resp := &sudosocpb.Services{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (rpc *Server) ServiceDetail(ctx context.Context, req *sudosocpb.ServiceDetailReq) (*sudosocpb.ServiceDetail, error) {
	resp := &sudosocpb.ServiceDetail{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// StartService creates and starts a Windows service on a remote host
func (rpc *Server) StartService(ctx context.Context, req *sudosocpb.StartServiceReq) (*sudosocpb.ServiceInfo, error) {
	resp := &sudosocpb.ServiceInfo{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (rpc *Server) StartServiceByName(ctx context.Context, req *sudosocpb.StartServiceByNameReq) (*sudosocpb.ServiceInfo, error) {
	resp := &sudosocpb.ServiceInfo{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// StopService stops a remote service
func (rpc *Server) StopService(ctx context.Context, req *sudosocpb.StopServiceReq) (*sudosocpb.ServiceInfo, error) {
	resp := &sudosocpb.ServiceInfo{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// RemoveService deletes a service from the remote system
func (rpc *Server) RemoveService(ctx context.Context, req *sudosocpb.RemoveServiceReq) (*sudosocpb.ServiceInfo, error) {
	resp := &sudosocpb.ServiceInfo{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
