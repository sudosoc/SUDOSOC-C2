//go:build server && go_sqlite && sudosoc_e2e

package c2_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	implantHandlers "github.com/sudosoc/SUDOSOC-C2/implant/sliver/handlers"
	implantWG "github.com/sudosoc/SUDOSOC-C2/implant/sliver/transports/wireguard"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/commonpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/rpcpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
	"github.com/sudosoc/SUDOSOC-C2/server/c2"
	"github.com/sudosoc/SUDOSOC-C2/server/core"
	"github.com/sudosoc/SUDOSOC-C2/server/transport"
	"github.com/google/uuid"
	"github.com/hashicorp/yamux"
	"google.golang.org/protobuf/proto"
)

func TestWGYamux_EndToEndPingRPC(t *testing.T) {
	// NOTE: If you run this test in a restricted environment where writes to
	// `~/.sudosoc` are blocked, set `SUDOSOC_ROOT_DIR` to a writable temp dir.

	t.Cleanup(func() {
		for _, session := range core.Sessions.All() {
			core.Sessions.Remove(session.ID)
		}
	})

	grpcServer, grpcListener, err := transport.LocalListener()
	if err != nil {
		t.Fatalf("start local grpc listener: %v", err)
	}
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = grpcListener.Close()
	})

	serverConn, implantConn := net.Pipe()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = implantConn.Close()
	})
	go c2.HandleWGSliverConnectionForTest(serverConn)

	stopImplant := startTestWGImplant(t, implantConn)
	t.Cleanup(stopImplant)

	sessionID := waitForSessionID(t, 10*time.Second)

	rpcConn, err := dialBufConn(context.Background(), grpcListener)
	if err != nil {
		t.Fatalf("dial grpc/bufconn: %v", err)
	}
	t.Cleanup(func() { _ = rpcConn.Close() })
	rpcClient := rpcpb.NewCoreRPCClient(rpcConn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pingReq := &sudosocpb.Ping{
		Nonce: 47443,
		Request: &commonpb.Request{
			SessionID: sessionID,
			Timeout:   int64(5 * time.Second),
		},
	}
	pingResp, err := rpcClient.Ping(ctx, pingReq)
	if err != nil {
		t.Fatalf("rpc ping: %v", err)
	}
	if pingResp.Nonce != pingReq.Nonce {
		t.Fatalf("unexpected ping nonce: got=%d want=%d", pingResp.Nonce, pingReq.Nonce)
	}

	const concurrentPings = 32
	var wg sync.WaitGroup
	errCh := make(chan error, concurrentPings)

	for i := 0; i < concurrentPings; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			callCtx, callCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer callCancel()

			req := &sudosocpb.Ping{
				Nonce: int32(i),
				Request: &commonpb.Request{
					SessionID: sessionID,
					Timeout:   int64(5 * time.Second),
				},
			}
			resp, err := rpcClient.Ping(callCtx, req)
			if err != nil {
				errCh <- err
				return
			}
			if resp.Nonce != req.Nonce {
				errCh <- fmt.Errorf("ping nonce mismatch: got=%d want=%d", resp.Nonce, req.Nonce)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

func TestWGYamux_EndToEndMixedRPCs(t *testing.T) {
	// NOTE: If you run this test in a restricted environment where writes to
	// `~/.sudosoc` are blocked, set `SUDOSOC_ROOT_DIR` to a writable temp dir.

	t.Cleanup(func() {
		for _, session := range core.Sessions.All() {
			core.Sessions.Remove(session.ID)
		}
	})

	grpcServer, grpcListener, err := transport.LocalListener()
	if err != nil {
		t.Fatalf("start local grpc listener: %v", err)
	}
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = grpcListener.Close()
	})

	serverConn, implantConn := net.Pipe()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = implantConn.Close()
	})
	go c2.HandleWGSliverConnectionForTest(serverConn)

	stopImplant := startTestWGImplant(t, implantConn)
	t.Cleanup(stopImplant)

	sessionID := waitForSessionID(t, 10*time.Second)

	rpcConn, err := dialBufConn(context.Background(), grpcListener)
	if err != nil {
		t.Fatalf("dial grpc/bufconn: %v", err)
	}
	t.Cleanup(func() { _ = rpcConn.Close() })
	rpcClient := rpcpb.NewCoreRPCClient(rpcConn)

	testDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(testDir, "alpha.txt"), []byte("alpha"), 0600); err != nil {
		t.Fatalf("write alpha.txt: %v", err)
	}
	if err := os.Mkdir(filepath.Join(testDir, "subdir"), 0700); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}

	reqTimeout := int64(5 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pwdResp, err := rpcClient.Pwd(ctx, &sudosocpb.PwdReq{
		Request: &commonpb.Request{
			SessionID: sessionID,
			Timeout:   reqTimeout,
		},
	})
	if err != nil {
		t.Fatalf("rpc pwd: %v", err)
	}
	if pwdResp.Path == "" {
		t.Fatalf("unexpected empty pwd path")
	}

	envResp, err := rpcClient.GetEnv(ctx, &sudosocpb.EnvReq{
		Name: "PATH",
		Request: &commonpb.Request{
			SessionID: sessionID,
			Timeout:   reqTimeout,
		},
	})
	if err != nil {
		t.Fatalf("rpc getenv: %v", err)
	}
	if len(envResp.Variables) != 1 || envResp.Variables[0].Key != "PATH" {
		t.Fatalf("unexpected getenv response: %+v", envResp.Variables)
	}

	lsResp, err := rpcClient.Ls(ctx, &sudosocpb.LsReq{
		Path: testDir,
		Request: &commonpb.Request{
			SessionID: sessionID,
			Timeout:   reqTimeout,
		},
	})
	if err != nil {
		t.Fatalf("rpc ls: %v", err)
	}
	if !lsResp.Exists {
		t.Fatalf("unexpected ls response (Exists=false): %v", lsResp.GetResponse())
	}
	lsNames := map[string]bool{}
	for _, file := range lsResp.Files {
		lsNames[file.Name] = true
	}
	for _, want := range []string{"alpha.txt", "subdir"} {
		if !lsNames[want] {
			t.Fatalf("ls missing expected entry %q (got %d entries)", want, len(lsResp.Files))
		}
	}

	const concurrentCalls = 64
	var wg sync.WaitGroup
	errCh := make(chan error, concurrentCalls)

	for i := 0; i < concurrentCalls; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			callCtx, callCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer callCancel()

			switch i % 4 {
			case 0:
				req := &sudosocpb.Ping{
					Nonce: int32(i),
					Request: &commonpb.Request{
						SessionID: sessionID,
						Timeout:   reqTimeout,
					},
				}
				resp, err := rpcClient.Ping(callCtx, req)
				if err != nil {
					errCh <- err
					return
				}
				if resp.Nonce != req.Nonce {
					errCh <- fmt.Errorf("ping nonce mismatch: got=%d want=%d", resp.Nonce, req.Nonce)
					return
				}

			case 1:
				resp, err := rpcClient.Pwd(callCtx, &sudosocpb.PwdReq{
					Request: &commonpb.Request{
						SessionID: sessionID,
						Timeout:   reqTimeout,
					},
				})
				if err != nil {
					errCh <- err
					return
				}
				if resp.Path == "" {
					errCh <- fmt.Errorf("pwd returned empty path")
					return
				}

			case 2:
				resp, err := rpcClient.GetEnv(callCtx, &sudosocpb.EnvReq{
					Name: "PATH",
					Request: &commonpb.Request{
						SessionID: sessionID,
						Timeout:   reqTimeout,
					},
				})
				if err != nil {
					errCh <- err
					return
				}
				if len(resp.Variables) != 1 || resp.Variables[0].Key != "PATH" {
					errCh <- fmt.Errorf("unexpected getenv response: %+v", resp.Variables)
					return
				}

			default:
				resp, err := rpcClient.Ls(callCtx, &sudosocpb.LsReq{
					Path: testDir,
					Request: &commonpb.Request{
						SessionID: sessionID,
						Timeout:   reqTimeout,
					},
				})
				if err != nil {
					errCh <- err
					return
				}
				if !resp.Exists {
					errCh <- fmt.Errorf("unexpected ls response (Exists=false): %v", resp.GetResponse())
					return
				}
				found := false
				for _, file := range resp.Files {
					if file.Name == "alpha.txt" {
						found = true
						break
					}
				}
				if !found {
					errCh <- fmt.Errorf("ls missing expected alpha.txt entry")
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

func startTestWGImplant(t *testing.T, conn net.Conn) func() {
	t.Helper()

	if _, err := conn.Write([]byte(implantWG.YamuxPreface)); err != nil {
		t.Fatalf("write yamux preface: %v", err)
	}

	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	muxSession, err := yamux.Client(conn, cfg)
	if err != nil {
		t.Fatalf("start yamux client session: %v", err)
	}

	register := &sudosocpb.Register{
		Name:              "e2e",
		Hostname:          "localhost",
		Uuid:              uuid.NewString(),
		Username:          "unit-test",
		Os:                runtime.GOOS,
		Arch:              runtime.GOARCH,
		Pid:               int32(os.Getpid()),
		Filename:          "sliver-e2e",
		ActiveC2:          "wg://e2e",
		Version:           "e2e",
		ReconnectInterval: 0,
		ProxyURL:          "",
		Locale:            "en_US",
	}
	regData, err := proto.Marshal(register)
	if err != nil {
		t.Fatalf("marshal register: %v", err)
	}
	if err := sendWGYamuxEnvelope(muxSession, &sudosocpb.Envelope{Type: sudosocpb.MsgRegister, Data: regData}); err != nil {
		t.Fatalf("send register: %v", err)
	}

	handlers := implantHandlers.GetSystemHandlers()
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)

		streamSem := make(chan struct{}, 128)
		for {
			stream, err := muxSession.Accept()
			if err != nil {
				return
			}
			select {
			case streamSem <- struct{}{}:
			default:
				_ = stream.Close()
				continue
			}

			go func(stream net.Conn) {
				defer func() { <-streamSem }()
				defer stream.Close()

				envelope, err := implantWG.ReadEnvelope(stream)
				if err != nil || envelope == nil || envelope.ID == 0 {
					return
				}

				handler, ok := handlers[envelope.Type]
				if !ok {
					_ = sendWGYamuxEnvelope(muxSession, &sudosocpb.Envelope{ID: envelope.ID, UnknownMessageType: true})
					return
				}
				handler(envelope.Data, func(data []byte, err error) {
					_ = err
					_ = sendWGYamuxEnvelope(muxSession, &sudosocpb.Envelope{ID: envelope.ID, Data: data})
				})
			}(stream)
		}
	}()

	return func() {
		_ = muxSession.Close()
		_ = conn.Close()
		select {
		case <-loopDone:
		case <-time.After(5 * time.Second):
		}
	}
}

func sendWGYamuxEnvelope(session *yamux.Session, envelope *sudosocpb.Envelope) error {
	stream, err := session.Open()
	if err != nil {
		return err
	}
	defer stream.Close()
	return implantWG.WriteEnvelope(stream, envelope)
}
