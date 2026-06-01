package aitools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sudosoc/SUDOSOC-C2/protobuf/clientpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/commonpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
	serverassets "github.com/sudosoc/SUDOSOC-C2/server/assets"
)

func TestSearchAliasesIncludesTargetCompatibility(t *testing.T) {
	rootDir := t.TempDir()
	t.Setenv("SUDOSOC_ROOT_DIR", rootDir)

	aliasDir := filepath.Join(serverassets.GetAIAliasesDir(), "Rubeus")
	if err := os.MkdirAll(aliasDir, 0o700); err != nil {
		t.Fatalf("mkdir alias dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(aliasDir, "Rubeus.exe"), []byte("alias-binary"), 0o600); err != nil {
		t.Fatalf("write alias artifact: %v", err)
	}
	if err := os.WriteFile(filepath.Join(aliasDir, aiAliasManifestFileName), []byte(`{
		"name":"Rubeus",
		"version":"1.0.0",
		"command_name":"rubeus",
		"original_author":"GhostPack",
		"repo_url":"https://example.test/rubeus",
		"help":"Kerberos abuse helper",
		"entrypoint":"Main",
		"allow_args":true,
		"default_args":"",
		"is_reflective":false,
		"is_assembly":true,
		"files":[{"os":"windows","arch":"amd64","path":"Rubeus.exe"}]
	}`), 0o600); err != nil {
		t.Fatalf("write alias manifest: %v", err)
	}

	backend := &fakePackageBackend{
		sessions: &clientpb.Sessions{
			Sessions: []*clientpb.Session{
				{ID: "session-1", OS: "windows", Arch: "amd64", Hostname: "winhost"},
			},
		},
	}
	executor := &executor{
		backend: backend,
		conversation: &clientpb.AIConversation{
			TargetSessionID: "session-1",
		},
	}

	raw, err := executor.callSearchAliases(context.Background(), searchPackagesArgs{
		Query:          "kerberos",
		OnlyCompatible: true,
	})
	if err != nil {
		t.Fatalf("search aliases: %v", err)
	}

	var resp aliasSearchResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal search result: %v", err)
	}
	if resp.ReturnedCount != 1 || resp.TotalMatches != 1 {
		t.Fatalf("unexpected alias search counts: %+v", resp)
	}
	if resp.Target == nil || resp.Target.SessionID != "session-1" {
		t.Fatalf("expected session target in response, got %+v", resp.Target)
	}
	if len(resp.Results) != 1 {
		t.Fatalf("expected one alias result, got %+v", resp.Results)
	}
	result := resp.Results[0]
	if !result.Compatible || !result.CompatibilityChecked {
		t.Fatalf("expected compatible alias result, got %+v", result)
	}
	if result.ExecutionMode != "assembly" {
		t.Fatalf("unexpected alias execution mode: %+v", result)
	}
	if !strings.HasSuffix(result.ArtifactPath, filepath.Join("Rubeus", "Rubeus.exe")) {
		t.Fatalf("unexpected alias artifact path: %q", result.ArtifactPath)
	}
}

func TestExecuteAliasRunsExecuteAssembly(t *testing.T) {
	rootDir := t.TempDir()
	t.Setenv("SUDOSOC_ROOT_DIR", rootDir)

	aliasDir := filepath.Join(serverassets.GetAIAliasesDir(), "Seatbelt")
	if err := os.MkdirAll(aliasDir, 0o700); err != nil {
		t.Fatalf("mkdir alias dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(aliasDir, "Seatbelt.exe"), []byte("seatbelt-binary"), 0o600); err != nil {
		t.Fatalf("write alias artifact: %v", err)
	}
	if err := os.WriteFile(filepath.Join(aliasDir, aiAliasManifestFileName), []byte(`{
		"name":"Seatbelt",
		"version":"1.0.0",
		"command_name":"seatbelt",
		"original_author":"GhostPack",
		"repo_url":"https://example.test/seatbelt",
		"help":"Host survey helper",
		"entrypoint":"Main",
		"allow_args":true,
		"default_args":"",
		"is_reflective":false,
		"is_assembly":true,
		"files":[{"os":"windows","arch":"amd64","path":"Seatbelt.exe"}]
	}`), 0o600); err != nil {
		t.Fatalf("write alias manifest: %v", err)
	}

	backend := &fakePackageBackend{
		sessions: &clientpb.Sessions{
			Sessions: []*clientpb.Session{
				{ID: "session-1", OS: "windows", Arch: "amd64", Hostname: "winhost"},
			},
		},
		executeAssemblyFn: func(_ context.Context, req *sudosocpb.ExecuteAssemblyReq) (*sudosocpb.ExecuteAssembly, error) {
			return &sudosocpb.ExecuteAssembly{
				Output:   []byte("assembly-output"),
				Response: &commonpb.Response{},
			}, nil
		},
	}
	executor := &executor{
		backend: backend,
		conversation: &clientpb.AIConversation{
			TargetSessionID: "session-1",
		},
	}

	raw, err := executor.callExecuteAlias(context.Background(), executeAliasArgs{
		CommandName: "seatbelt",
		Args:        []string{"WindowsCredentialFiles"},
	})
	if err != nil {
		t.Fatalf("execute alias: %v", err)
	}

	if len(backend.executeAssemblyReqs) != 1 {
		t.Fatalf("expected execute-assembly request, got %d", len(backend.executeAssemblyReqs))
	}
	req := backend.executeAssemblyReqs[0]
	if req.GetRequest().GetSessionID() != "session-1" {
		t.Fatalf("unexpected target request: %+v", req.GetRequest())
	}
	if req.GetProcess() != aiAliasDefaultHostProcess["windows"] {
		t.Fatalf("unexpected default process: %q", req.GetProcess())
	}
	if len(req.GetArguments()) != 1 || req.GetArguments()[0] != "WindowsCredentialFiles" {
		t.Fatalf("unexpected assembly args: %+v", req.GetArguments())
	}

	var resp aliasExecutionResult
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal alias execution result: %v", err)
	}
	if resp.OutputText != "assembly-output" {
		t.Fatalf("unexpected alias output: %+v", resp)
	}
	if resp.ExecutionMode != "assembly" {
		t.Fatalf("unexpected alias execution mode: %+v", resp)
	}
}

func TestExecuteExtensionRegistersDependencyForBOF(t *testing.T) {
	rootDir := t.TempDir()
	t.Setenv("SUDOSOC_ROOT_DIR", rootDir)

	coffLoaderDir := filepath.Join(serverassets.GetAIExtensionsDir(), "coff-loader")
	if err := os.MkdirAll(coffLoaderDir, 0o700); err != nil {
		t.Fatalf("mkdir coff-loader dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(coffLoaderDir, "coff-loader.x64.dll"), []byte("coff-loader-binary"), 0o600); err != nil {
		t.Fatalf("write dependency artifact: %v", err)
	}
	if err := os.WriteFile(filepath.Join(coffLoaderDir, aiExtensionManifestFileName), []byte(`{
		"name":"coff-loader",
		"package_name":"coff-loader",
		"version":"1.0.0",
		"extension_author":"sliver",
		"original_author":"sliver",
		"repo_url":"https://example.test/coff-loader",
		"commands":[
			{
				"command_name":"coff-loader",
				"help":"Load and run COFFs",
				"entrypoint":"LoadAndRun",
				"files":[{"os":"windows","arch":"amd64","path":"coff-loader.x64.dll"}]
			}
		]
	}`), 0o600); err != nil {
		t.Fatalf("write dependency manifest: %v", err)
	}

	nanodumpDir := filepath.Join(serverassets.GetAIExtensionsDir(), "nanodump")
	if err := os.MkdirAll(nanodumpDir, 0o700); err != nil {
		t.Fatalf("mkdir nanodump dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nanodumpDir, "nanodump.x64.o"), []byte("nanodump-bof"), 0o600); err != nil {
		t.Fatalf("write bof artifact: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nanodumpDir, aiExtensionManifestFileName), []byte(`{
		"name":"nanodump",
		"package_name":"nanodump",
		"version":"1.0.0",
		"extension_author":"sliver",
		"original_author":"sliver",
		"repo_url":"https://example.test/nanodump",
		"commands":[
			{
				"command_name":"nanodump",
				"help":"Dump LSASS",
				"entrypoint":"go",
				"depends_on":"coff-loader",
				"files":[{"os":"windows","arch":"amd64","path":"nanodump.x64.o"}],
				"arguments":[
					{"name":"pid","type":"int","desc":"PID to dump","optional":false}
				]
			}
		]
	}`), 0o600); err != nil {
		t.Fatalf("write bof manifest: %v", err)
	}

	backend := &fakePackageBackend{
		sessions: &clientpb.Sessions{
			Sessions: []*clientpb.Session{
				{ID: "session-1", OS: "windows", Arch: "amd64", Hostname: "winhost"},
			},
		},
		listExtensionsFn: func(_ context.Context, _ *sudosocpb.ListExtensionsReq) (*sudosocpb.ListExtensions, error) {
			return &sudosocpb.ListExtensions{
				Names:    []string{},
				Response: &commonpb.Response{},
			}, nil
		},
		registerExtensionFn: func(_ context.Context, _ *sudosocpb.RegisterExtensionReq) (*sudosocpb.RegisterExtension, error) {
			return &sudosocpb.RegisterExtension{Response: &commonpb.Response{}}, nil
		},
		callExtensionFn: func(_ context.Context, _ *sudosocpb.CallExtensionReq) (*sudosocpb.CallExtension, error) {
			return &sudosocpb.CallExtension{
				Output:   []byte("extension-output"),
				Response: &commonpb.Response{},
			}, nil
		},
	}
	executor := &executor{
		backend: backend,
		conversation: &clientpb.AIConversation{
			TargetSessionID: "session-1",
		},
	}

	raw, err := executor.callExecuteExtension(context.Background(), executeExtensionArgs{
		CommandName: "nanodump",
		NamedArgs: map[string]any{
			"pid": 1337,
		},
	})
	if err != nil {
		t.Fatalf("execute extension: %v", err)
	}

	if len(backend.listExtensionsReqs) != 1 {
		t.Fatalf("expected list-extensions request, got %d", len(backend.listExtensionsReqs))
	}
	if len(backend.registerExtensionReqs) != 1 {
		t.Fatalf("expected one dependency registration, got %d", len(backend.registerExtensionReqs))
	}
	registerReq := backend.registerExtensionReqs[0]
	if registerReq.GetOS() != "windows" {
		t.Fatalf("unexpected dependency registration target os: %+v", registerReq)
	}
	if string(registerReq.GetData()) != "coff-loader-binary" {
		t.Fatalf("expected dependency bytes to be registered, got %q", string(registerReq.GetData()))
	}

	if len(backend.callExtensionReqs) != 1 {
		t.Fatalf("expected one call-extension request, got %d", len(backend.callExtensionReqs))
	}
	callReq := backend.callExtensionReqs[0]
	if callReq.GetName() != registerReq.GetName() {
		t.Fatalf("expected BOF call to use dependency hash, got register=%q call=%q", registerReq.GetName(), callReq.GetName())
	}
	if callReq.GetExport() != "LoadAndRun" {
		t.Fatalf("unexpected BOF dependency export: %+v", callReq)
	}
	if len(callReq.GetArgs()) == 0 {
		t.Fatalf("expected packed BOF arguments, got empty buffer")
	}

	var resp extensionExecutionResult
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal extension execution result: %v", err)
	}
	if resp.OutputText != "extension-output" {
		t.Fatalf("unexpected extension output: %+v", resp)
	}
	if resp.ExecutionMode != "bof" {
		t.Fatalf("expected bof execution mode, got %+v", resp)
	}
	if resp.DependencyRootPath == "" || resp.DependencyArtifactPath == "" {
		t.Fatalf("expected dependency metadata in response, got %+v", resp)
	}
}

type fakePackageBackend struct {
	sessions *clientpb.Sessions
	beacons  *clientpb.Beacons

	executeAssemblyFn   func(context.Context, *sudosocpb.ExecuteAssemblyReq) (*sudosocpb.ExecuteAssembly, error)
	listExtensionsFn    func(context.Context, *sudosocpb.ListExtensionsReq) (*sudosocpb.ListExtensions, error)
	registerExtensionFn func(context.Context, *sudosocpb.RegisterExtensionReq) (*sudosocpb.RegisterExtension, error)
	callExtensionFn     func(context.Context, *sudosocpb.CallExtensionReq) (*sudosocpb.CallExtension, error)

	executeAssemblyReqs   []*sudosocpb.ExecuteAssemblyReq
	listExtensionsReqs    []*sudosocpb.ListExtensionsReq
	registerExtensionReqs []*sudosocpb.RegisterExtensionReq
	callExtensionReqs     []*sudosocpb.CallExtensionReq
}

func (f *fakePackageBackend) GetSessions(context.Context, *commonpb.Empty) (*clientpb.Sessions, error) {
	if f.sessions == nil {
		return &clientpb.Sessions{}, nil
	}
	return f.sessions, nil
}

func (f *fakePackageBackend) GetBeacons(context.Context, *commonpb.Empty) (*clientpb.Beacons, error) {
	if f.beacons == nil {
		return &clientpb.Beacons{}, nil
	}
	return f.beacons, nil
}

func (*fakePackageBackend) Ls(context.Context, *sudosocpb.LsReq) (*sudosocpb.Ls, error) {
	return &sudosocpb.Ls{Response: &commonpb.Response{}}, nil
}

func (*fakePackageBackend) Mv(context.Context, *sudosocpb.MvReq) (*sudosocpb.Mv, error) {
	return &sudosocpb.Mv{Response: &commonpb.Response{}}, nil
}

func (*fakePackageBackend) Cp(context.Context, *sudosocpb.CpReq) (*sudosocpb.Cp, error) {
	return &sudosocpb.Cp{Response: &commonpb.Response{}}, nil
}

func (*fakePackageBackend) Rm(context.Context, *sudosocpb.RmReq) (*sudosocpb.Rm, error) {
	return &sudosocpb.Rm{Response: &commonpb.Response{}}, nil
}

func (*fakePackageBackend) Mkdir(context.Context, *sudosocpb.MkdirReq) (*sudosocpb.Mkdir, error) {
	return &sudosocpb.Mkdir{Response: &commonpb.Response{}}, nil
}

func (*fakePackageBackend) Cd(context.Context, *sudosocpb.CdReq) (*sudosocpb.Pwd, error) {
	return &sudosocpb.Pwd{Response: &commonpb.Response{}}, nil
}

func (*fakePackageBackend) Download(context.Context, *sudosocpb.DownloadReq) (*sudosocpb.Download, error) {
	return &sudosocpb.Download{Response: &commonpb.Response{}}, nil
}

func (*fakePackageBackend) Pwd(context.Context, *sudosocpb.PwdReq) (*sudosocpb.Pwd, error) {
	return &sudosocpb.Pwd{Response: &commonpb.Response{}}, nil
}

func (*fakePackageBackend) Chmod(context.Context, *sudosocpb.ChmodReq) (*sudosocpb.Chmod, error) {
	return &sudosocpb.Chmod{Response: &commonpb.Response{}}, nil
}

func (*fakePackageBackend) Chown(context.Context, *sudosocpb.ChownReq) (*sudosocpb.Chown, error) {
	return &sudosocpb.Chown{Response: &commonpb.Response{}}, nil
}

func (*fakePackageBackend) Chtimes(context.Context, *sudosocpb.ChtimesReq) (*sudosocpb.Chtimes, error) {
	return &sudosocpb.Chtimes{Response: &commonpb.Response{}}, nil
}

func (*fakePackageBackend) Mount(context.Context, *sudosocpb.MountReq) (*sudosocpb.Mount, error) {
	return &sudosocpb.Mount{Response: &commonpb.Response{}}, nil
}

func (*fakePackageBackend) Ifconfig(context.Context, *sudosocpb.IfconfigReq) (*sudosocpb.Ifconfig, error) {
	return &sudosocpb.Ifconfig{Response: &commonpb.Response{}}, nil
}

func (*fakePackageBackend) Netstat(context.Context, *sudosocpb.NetstatReq) (*sudosocpb.Netstat, error) {
	return &sudosocpb.Netstat{Response: &commonpb.Response{}}, nil
}

func (*fakePackageBackend) Ps(context.Context, *sudosocpb.PsReq) (*sudosocpb.Ps, error) {
	return &sudosocpb.Ps{Response: &commonpb.Response{}}, nil
}

func (*fakePackageBackend) GetEnv(context.Context, *sudosocpb.EnvReq) (*sudosocpb.EnvInfo, error) {
	return &sudosocpb.EnvInfo{Response: &commonpb.Response{}}, nil
}

func (*fakePackageBackend) Ping(context.Context, *sudosocpb.Ping) (*sudosocpb.Ping, error) {
	return &sudosocpb.Ping{Response: &commonpb.Response{}}, nil
}

func (*fakePackageBackend) Screenshot(context.Context, *sudosocpb.ScreenshotReq) (*sudosocpb.Screenshot, error) {
	return &sudosocpb.Screenshot{Response: &commonpb.Response{}}, nil
}

func (*fakePackageBackend) Execute(context.Context, *sudosocpb.ExecuteReq) (*sudosocpb.Execute, error) {
	return &sudosocpb.Execute{Response: &commonpb.Response{}}, nil
}

func (*fakePackageBackend) ExecuteWindows(context.Context, *sudosocpb.ExecuteWindowsReq) (*sudosocpb.Execute, error) {
	return &sudosocpb.Execute{Response: &commonpb.Response{}}, nil
}

func (f *fakePackageBackend) ExecuteAssembly(ctx context.Context, req *sudosocpb.ExecuteAssemblyReq) (*sudosocpb.ExecuteAssembly, error) {
	f.executeAssemblyReqs = append(f.executeAssemblyReqs, req)
	if f.executeAssemblyFn != nil {
		return f.executeAssemblyFn(ctx, req)
	}
	return &sudosocpb.ExecuteAssembly{Response: &commonpb.Response{}}, nil
}

func (*fakePackageBackend) Sideload(context.Context, *sudosocpb.SideloadReq) (*sudosocpb.Sideload, error) {
	return &sudosocpb.Sideload{Response: &commonpb.Response{}}, nil
}

func (*fakePackageBackend) SpawnDll(context.Context, *sudosocpb.InvokeSpawnDllReq) (*sudosocpb.SpawnDll, error) {
	return &sudosocpb.SpawnDll{Response: &commonpb.Response{}}, nil
}

func (f *fakePackageBackend) RegisterExtension(ctx context.Context, req *sudosocpb.RegisterExtensionReq) (*sudosocpb.RegisterExtension, error) {
	f.registerExtensionReqs = append(f.registerExtensionReqs, req)
	if f.registerExtensionFn != nil {
		return f.registerExtensionFn(ctx, req)
	}
	return &sudosocpb.RegisterExtension{Response: &commonpb.Response{}}, nil
}

func (f *fakePackageBackend) ListExtensions(ctx context.Context, req *sudosocpb.ListExtensionsReq) (*sudosocpb.ListExtensions, error) {
	f.listExtensionsReqs = append(f.listExtensionsReqs, req)
	if f.listExtensionsFn != nil {
		return f.listExtensionsFn(ctx, req)
	}
	return &sudosocpb.ListExtensions{Response: &commonpb.Response{}}, nil
}

func (f *fakePackageBackend) CallExtension(ctx context.Context, req *sudosocpb.CallExtensionReq) (*sudosocpb.CallExtension, error) {
	f.callExtensionReqs = append(f.callExtensionReqs, req)
	if f.callExtensionFn != nil {
		return f.callExtensionFn(ctx, req)
	}
	return &sudosocpb.CallExtension{Response: &commonpb.Response{}}, nil
}
