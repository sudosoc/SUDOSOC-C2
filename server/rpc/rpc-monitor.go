package rpc

import (
	"context"

	"github.com/sudosoc/SUDOSOC-C2/protobuf/clientpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/commonpb"
	"github.com/sudosoc/SUDOSOC-C2/server/watchtower"
)

func (rpc *Server) MonitorStart(ctx context.Context, _ *commonpb.Empty) (*commonpb.Response, error) {
	resp := &commonpb.Response{}
	config, _ := watchtower.ListConfig()
	err := watchtower.StartWatchTower(config)
	if err != nil {
		resp.Err = err.Error()
	}
	return resp, rpcError(err)
}

func (rpc *Server) MonitorStop(ctx context.Context, _ *commonpb.Empty) (*commonpb.Empty, error) {
	resp := &commonpb.Empty{}
	watchtower.StopWatchTower()
	return resp, nil
}

func (rpc *Server) MonitorListConfig(ctx context.Context, _ *commonpb.Empty) (*clientpb.MonitoringProviders, error) {
	resp, err := watchtower.ListConfig()
	if err != nil {
		return nil, rpcError(err)
	}
	return resp, nil
}

func (rpc *Server) MonitorAddConfig(ctx context.Context, m *clientpb.MonitoringProvider) (*commonpb.Response, error) {
	resp := &commonpb.Response{}
	err := watchtower.AddConfig(m)
	if err != nil {
		resp.Err = err.Error()
	}
	return resp, nil
}

func (rpc *Server) MonitorDelConfig(ctx context.Context, m *clientpb.MonitoringProvider) (*commonpb.Response, error) {
	resp := &commonpb.Response{}
	err := watchtower.DelConfig(m)
	if err != nil {
		resp.Err = err.Error()
	}
	return resp, nil
}
