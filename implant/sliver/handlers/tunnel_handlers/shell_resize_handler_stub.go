//go:build !darwin && !linux && !freebsd && !openbsd && !dragonfly

package tunnel_handlers

import (
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/transports"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/commonpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
	"google.golang.org/protobuf/proto"
)

func ShellResizeReqHandler(envelope *sudosocpb.Envelope, connection *transports.Connection) {
	resp, _ := proto.Marshal(&commonpb.Empty{})
	connection.Send <- &sudosocpb.Envelope{
		ID:   envelope.ID,
		Data: resp,
	}
}
