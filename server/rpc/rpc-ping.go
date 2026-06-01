package rpc

import (
	"context"

	"github.com/sudosoc/SUDOSOC-C2/protobuf/commonpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
)

// Ping - Try to send a round trip message to the implant
func (rpc *Server) Ping(ctx context.Context, req *sudosocpb.Ping) (*sudosocpb.Ping, error) {
	resp := &sudosocpb.Ping{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
