package tasks

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
	"os"
	"strings"
	"time"

	"github.com/sudosoc/SUDOSOC-C2/client/command/environment"
	"github.com/sudosoc/SUDOSOC-C2/client/command/exec"
	"github.com/sudosoc/SUDOSOC-C2/client/command/extensions"
	"github.com/sudosoc/SUDOSOC-C2/client/command/filesystem"
	"github.com/sudosoc/SUDOSOC-C2/client/command/network"
	"github.com/sudosoc/SUDOSOC-C2/client/command/privilege"
	"github.com/sudosoc/SUDOSOC-C2/client/command/processes"
	"github.com/sudosoc/SUDOSOC-C2/client/command/registry"
	"github.com/sudosoc/SUDOSOC-C2/client/command/settings"
	"github.com/sudosoc/SUDOSOC-C2/client/console"
	"github.com/sudosoc/SUDOSOC-C2/client/constants"
	"github.com/sudosoc/SUDOSOC-C2/client/forms"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/clientpb"
	"github.com/sudosoc/SUDOSOC-C2/protobuf/sudosocpb"
	"github.com/sudosoc/SUDOSOC-C2/util"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"google.golang.org/protobuf/proto"
)

// TasksFetchCmd - Manage beacon tasks.
func TasksFetchCmd(cmd *cobra.Command, con *console.SudosocClient, args []string) {
	beacon := con.ActiveTarget.GetBeaconInteractive()
	if beacon == nil {
		return
	}
	beaconTasks, err := con.Rpc.GetBeaconTasks(context.Background(), &clientpb.Beacon{ID: beacon.ID})
	if err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}
	tasks := beaconTasks.Tasks
	if len(tasks) == 0 {
		con.PrintErrorf("No tasks for beacon\n")
		return
	}

	var idArg string
	if len(args) > 0 {
		idArg = args[0]
	}
	if idArg != "" {
		tasks = filterTasksByID(idArg, tasks)
		if len(tasks) == 0 {
			con.PrintErrorf("No beacon task found with id %s\n", idArg)
			return
		}
	}

	filter, _ := cmd.Flags().GetString("filter")
	if filter != "" {
		tasks = filterTasksByTaskType(filter, tasks)
		if len(tasks) == 0 {
			con.PrintErrorf("No beacon tasks with filter type '%s'\n", filter)
			return
		}
	}

	var task *clientpb.BeaconTask
	if 1 < len(tasks) {
		task, err = SelectBeaconTask(tasks)
		if err != nil {
			con.PrintErrorf("%s\n", err)
			return
		}
		con.Printf(console.UpN+console.Clearln, 1)
	} else {
		task = tasks[0]
	}
	task, err = con.Rpc.GetBeaconTaskContent(context.Background(), &clientpb.BeaconTask{ID: task.ID})
	if err != nil {
		con.PrintErrorf("Failed to fetch task content: %s\n", err)
		return
	}
	PrintTask(task, con)
}

func filterTasksByID(taskID string, tasks []*clientpb.BeaconTask) []*clientpb.BeaconTask {
	filteredTasks := []*clientpb.BeaconTask{}
	for _, task := range tasks {
		if strings.HasPrefix(task.ID, strings.ToLower(taskID)) {
			filteredTasks = append(filteredTasks, task)
		}
	}
	return filteredTasks
}

func filterTasksByTaskType(taskType string, tasks []*clientpb.BeaconTask) []*clientpb.BeaconTask {
	filteredTasks := []*clientpb.BeaconTask{}
	for _, task := range tasks {
		if strings.HasPrefix(strings.ToLower(task.Description), strings.ToLower(taskType)) {
			filteredTasks = append(filteredTasks, task)
		}
	}
	return filteredTasks
}

// PrintTask - Print the details of a beacon task.
func PrintTask(task *clientpb.BeaconTask, con *console.SudosocClient) {
	tw := table.NewWriter()
	tw.SetStyle(settings.GetTableWithBordersStyle(con))
	tw.AppendRow(table.Row{console.StyleBold.Render("Beacon Task"), task.ID})
	tw.AppendSeparator()
	tw.AppendRow(table.Row{"State", emojiState(task.State) + " " + prettyState(strings.Title(task.State))})
	tw.AppendRow(table.Row{"Description", task.Description})
	tw.AppendRow(table.Row{"Created", time.Unix(task.CreatedAt, 0).Format(time.RFC1123)})
	if !time.Unix(task.SentAt, 0).IsZero() {
		tw.AppendRow(table.Row{"Sent", time.Unix(task.SentAt, 0).Format(time.RFC1123)})
	}
	if !time.Unix(task.CompletedAt, 0).IsZero() {
		tw.AppendRow(table.Row{"Completed", time.Unix(task.CompletedAt, 0).Format(time.RFC1123)})
	}

	tw.AppendRow(table.Row{"Request Size", util.ByteCountBinary(int64(len(task.Request)))})
	if !time.Unix(task.CompletedAt, 0).IsZero() {
		tw.AppendRow(table.Row{"Response Size", util.ByteCountBinary(int64(len(task.Response)))})
	}
	tw.AppendSeparator()
	con.Printf("%s\n", tw.Render())
	if !time.Unix(task.CompletedAt, 0).IsZero() {
		con.Println()
		if 0 < len(task.Response) {
			renderTaskResponse(task, con)
		} else {
			con.PrintInfof("No task response\n")
		}
	}
}

func emojiState(state string) string {
	switch strings.ToLower(state) {
	case "completed":
		return "✅"
	case "pending":
		return "⏳"
	case "failed":
		return "❌"
	case "canceled":
		return "🚫"
	default:
		return "❓"
	}
}

// Decode and render message specific content.
func renderTaskResponse(task *clientpb.BeaconTask, con *console.SudosocClient) {
	reqEnvelope := &sudosocpb.Envelope{}
	proto.Unmarshal(task.Request, reqEnvelope)
	switch reqEnvelope.Type {

	// ---------------------
	// Environment commands
	// ---------------------
	case sudosocpb.MsgEnvReq:
		envInfo := &sudosocpb.EnvInfo{}
		err := proto.Unmarshal(task.Response, envInfo)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		environment.PrintGetEnvInfo(envInfo, con)

	case sudosocpb.MsgSetEnvReq:
		setEnvReq := &sudosocpb.SetEnvReq{}
		err := proto.Unmarshal(task.Request, setEnvReq)
		if err != nil {
			con.PrintErrorf("Failed to decode task request: %s\n", err)
			return
		}
		setEnv := &sudosocpb.SetEnv{}
		err = proto.Unmarshal(task.Response, setEnv)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		environment.PrintSetEnvInfo(setEnvReq.Variable.Key, setEnvReq.Variable.Value, setEnv, con)

	case sudosocpb.MsgUnsetEnvReq:
		unsetEnvReq := &sudosocpb.UnsetEnvReq{}
		err := proto.Unmarshal(task.Request, unsetEnvReq)
		if err != nil {
			con.PrintErrorf("Failed to decode task request: %s\n", err)
			return
		}
		unsetEnv := &sudosocpb.UnsetEnv{}
		err = proto.Unmarshal(task.Response, unsetEnv)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		environment.PrintUnsetEnvInfo(unsetEnvReq.Name, unsetEnv, con)

	// ---------------------
	// Call extension commands
	// ---------------------
	case sudosocpb.MsgCallExtensionReq:
		callExtension := &sudosocpb.CallExtension{}
		err := proto.Unmarshal(task.Response, callExtension)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		extensions.PrintExtOutput("", "", nil, callExtension, con)

	// ---------------------
	// Exec commands
	// ---------------------
	case sudosocpb.MsgInvokeExecuteAssemblyReq:
		fallthrough
	case sudosocpb.MsgInvokeInProcExecuteAssemblyReq:
		fallthrough
	case sudosocpb.MsgExecuteAssemblyReq:
		execAssembly := &sudosocpb.ExecuteAssembly{}
		err := proto.Unmarshal(task.Response, execAssembly)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		beacon, _ := con.Rpc.GetBeacon(context.Background(), &clientpb.Beacon{ID: task.BeaconID})
		hostname := "hostname"
		if beacon != nil {
			hostname = beacon.Hostname
		}
		assemblyPath := ""

		f := pflag.NewFlagSet(constants.ExecuteAssemblyStr, pflag.ContinueOnError)
		f.BoolP("save", "s", false, "save output to file")
		f.BoolP("loot", "X", false, "save output as loot")
		f.StringP("name", "n", "", "name to assign loot (optional)")

		assemblyCmd := &cobra.Command{Use: constants.ExecuteAssemblyStr}
		assemblyCmd.Flags().AddFlagSet(f)

		exec.HandleExecuteAssemblyResponse(execAssembly, assemblyPath, hostname, assemblyCmd, con)

	// execute-shellcode
	case sudosocpb.MsgTaskReq:
		shellcodeExec := &sudosocpb.Task{}
		err := proto.Unmarshal(task.Response, shellcodeExec)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		exec.PrintExecuteShellcode(shellcodeExec, con)

	case sudosocpb.MsgExecuteReq:
		execReq := &sudosocpb.ExecuteReq{}
		err := proto.Unmarshal(reqEnvelope.Data, execReq)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		execResult := &sudosocpb.Execute{}
		err = proto.Unmarshal(task.Response, execResult)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}

		f := pflag.NewFlagSet(constants.ExecuteStr, pflag.ContinueOnError)
		f.BoolP("output", "o", execReq.Output, "capture command output")
		f.Bool("background", execReq.Background, "start the process in the background and track it")
		f.BoolP("loot", "X", false, "save output as loot")
		f.BoolP("ignore-stderr", "S", false, "don't print STDERR output")
		f.StringP("stdout", "O", execReq.Stdout, "remote path to redirect STDOUT to")
		f.StringP("stderr", "E", execReq.Stderr, "remote path to redirect STDERR to")

		execCmd := &cobra.Command{Use: constants.ExecuteStr}
		execCmd.Flags().AddFlagSet(f)
		execCmd.SetArgs(append([]string{execReq.Path}, execReq.Args...))

		exec.PrintExecute(execResult, execCmd, con)

	case sudosocpb.MsgExecuteChildrenReq:
		execChildren := &sudosocpb.ExecuteChildren{}
		err := proto.Unmarshal(task.Response, execChildren)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		exec.PrintExecuteChildren(execChildren, con)

	case sudosocpb.MsgSideloadReq:
		sideload := &sudosocpb.Sideload{}
		err := proto.Unmarshal(task.Response, sideload)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		beacon, _ := con.Rpc.GetBeacon(context.Background(), &clientpb.Beacon{ID: task.BeaconID})
		hostname := "hostname"
		if beacon != nil {
			hostname = beacon.Hostname
		}

		f := pflag.NewFlagSet(constants.SideloadStr, pflag.ContinueOnError)
		f.BoolP("save", "s", false, "save output to file")
		f.BoolP("loot", "X", false, "save output as loot")

		sideloadCmd := &cobra.Command{Use: constants.SideloadStr}
		sideloadCmd.Flags().AddFlagSet(f)

		exec.HandleSideloadResponse(sideload, "", hostname, sideloadCmd, con)

	case sudosocpb.MsgSpawnDllReq:
		spawnDll := &sudosocpb.SpawnDll{}
		err := proto.Unmarshal(task.Response, spawnDll)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		beacon, _ := con.Rpc.GetBeacon(context.Background(), &clientpb.Beacon{ID: task.BeaconID})
		hostname := "hostname"
		if beacon != nil {
			hostname = beacon.Hostname
		}

		f := pflag.NewFlagSet(constants.SpawnDllStr, pflag.ContinueOnError)
		f.BoolP("save", "s", false, "save output to file")
		f.BoolP("loot", "X", false, "save output as loot")

		spawnDllCmd := &cobra.Command{Use: constants.SpawnDllStr}
		spawnDllCmd.Flags().AddFlagSet(f)

		exec.HandleSpawnDLLResponse(spawnDll, "", hostname, spawnDllCmd, con)

	case sudosocpb.MsgSSHCommandReq:
		sshCommand := &sudosocpb.SSHCommand{}
		err := proto.Unmarshal(task.Response, sshCommand)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		exec.PrintSSHCmd(sshCommand, con)

	// ---------------------
	// File system commands
	// ---------------------
	// Cat = download
	case sudosocpb.MsgCdReq:
		pwd := &sudosocpb.Pwd{}
		err := proto.Unmarshal(task.Response, pwd)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		filesystem.PrintPwd(pwd, con)

	case sudosocpb.MsgDownloadReq:
		download := &sudosocpb.Download{}
		err := proto.Unmarshal(task.Response, download)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		taskResponseDownload(download, con)

	case sudosocpb.MsgLsReq:
		ls := &sudosocpb.Ls{}
		err := proto.Unmarshal(task.Response, ls)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}

		f := pflag.NewFlagSet("ls", pflag.ContinueOnError)
		f.BoolP("reverse", "r", false, "reverse sort order")
		f.BoolP("modified", "m", false, "sort by modified time")
		f.BoolP("size", "s", false, "sort by size")

		filesystem.PrintLs(ls, f, con)

	case sudosocpb.MsgMvReq:
		mv := &sudosocpb.Mv{}
		err := proto.Unmarshal(task.Response, mv)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}

	case sudosocpb.MsgMkdirReq:
		mkdir := &sudosocpb.Mkdir{}
		err := proto.Unmarshal(task.Response, mkdir)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		filesystem.PrintMkdir(mkdir, con)

	case sudosocpb.MsgPwdReq:
		pwd := &sudosocpb.Pwd{}
		err := proto.Unmarshal(task.Response, pwd)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		filesystem.PrintPwd(pwd, con)

	case sudosocpb.MsgRmReq:
		rm := &sudosocpb.Rm{}
		err := proto.Unmarshal(task.Response, rm)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		filesystem.PrintRm(rm, con)

	case sudosocpb.MsgUploadReq:
		upload := &sudosocpb.Upload{}
		err := proto.Unmarshal(task.Response, upload)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		filesystem.PrintUpload(upload, con)

	case sudosocpb.MsgChmodReq:
		chmod := &sudosocpb.Chmod{}
		err := proto.Unmarshal(task.Response, chmod)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		filesystem.PrintChmod(chmod, con)

	case sudosocpb.MsgChownReq:
		chown := &sudosocpb.Chown{}
		err := proto.Unmarshal(task.Response, chown)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		filesystem.PrintChown(chown, con)

	case sudosocpb.MsgChtimesReq:
		chtimes := &sudosocpb.Chtimes{}
		err := proto.Unmarshal(task.Response, chtimes)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		filesystem.PrintChtimes(chtimes, con)

	case sudosocpb.MsgMemfilesListReq:
		memfilesList := &sudosocpb.Ls{}
		err := proto.Unmarshal(task.Response, memfilesList)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		filesystem.PrintMemfiles(memfilesList, con)

	case sudosocpb.MsgMemfilesAddReq:
		memfilesAdd := &sudosocpb.MemfilesAdd{}
		err := proto.Unmarshal(task.Response, memfilesAdd)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		filesystem.PrintAddMemfile(memfilesAdd, con)

	case sudosocpb.MsgMemfilesRmReq:
		memfilesRm := &sudosocpb.MemfilesRm{}
		err := proto.Unmarshal(task.Response, memfilesRm)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		filesystem.PrintRmMemfile(memfilesRm, con)

	// ---------------------
	// Network commands
	// ---------------------
	case sudosocpb.MsgIfconfigReq:
		ifconfig := &sudosocpb.Ifconfig{}
		err := proto.Unmarshal(task.Response, ifconfig)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		network.PrintIfconfig(ifconfig, true, con)

	case sudosocpb.MsgNetstatReq:
		netstat := &sudosocpb.Netstat{}
		err := proto.Unmarshal(task.Response, netstat)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		beacon, err := con.Rpc.GetBeacon(context.Background(), &clientpb.Beacon{ID: task.BeaconID})
		if err != nil {
			con.PrintErrorf("Failed to fetch beacon: %s\n", err)
			return
		}
		network.PrintNetstat(netstat, beacon.PID, beacon.ActiveC2, false, con)

	// ---------------------
	// Privilege commands
	// ---------------------
	case sudosocpb.MsgGetPrivsReq:
		privs := &sudosocpb.GetPrivs{}
		err := proto.Unmarshal(task.Response, privs)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		beacon, err := con.Rpc.GetBeacon(context.Background(), &clientpb.Beacon{ID: task.BeaconID})
		if err != nil {
			con.PrintErrorf("Failed to fetch beacon: %s\n", err)
			return
		}
		privilege.PrintGetPrivs(privs, beacon.PID, con)

	case sudosocpb.MsgInvokeGetSystemReq:
		getSystem := &sudosocpb.GetSystem{}
		err := proto.Unmarshal(task.Response, getSystem)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		privilege.PrintGetSystem(getSystem, con)

	case sudosocpb.MsgCurrentTokenOwnerReq:
		cto := &sudosocpb.CurrentTokenOwner{}
		err := proto.Unmarshal(task.Response, cto)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}

	case sudosocpb.MsgImpersonateReq:
		impersonateReq := &sudosocpb.ImpersonateReq{}
		err := proto.Unmarshal(task.Response, impersonateReq)
		if err != nil {
			con.PrintErrorf("Failed to decode task request: %s\n", err)
			return
		}
		impersonate := &sudosocpb.Impersonate{}
		err = proto.Unmarshal(task.Response, impersonate)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		privilege.PrintImpersonate(impersonate, impersonateReq.Username, con)

	case sudosocpb.MsgMakeTokenReq:
		makeTokenReq := &sudosocpb.MakeTokenReq{}
		err := proto.Unmarshal(task.Response, makeTokenReq)
		if err != nil {
			con.PrintErrorf("Failed to decode task request: %s\n", err)
			return
		}
		makeToken := &sudosocpb.MakeToken{}
		err = proto.Unmarshal(task.Response, makeToken)
		if err != nil {
			con.PrintErrorf("Failed to decode task request: %s\n", err)
			return
		}
		privilege.PrintMakeToken(makeToken, makeTokenReq.Domain, makeTokenReq.Username, con)

	case sudosocpb.MsgRunAsReq:
		runAsReq := &sudosocpb.RunAsReq{}
		err := proto.Unmarshal(task.Response, runAsReq)
		if err != nil {
			con.PrintErrorf("Failed to decode task request: %s\n", err)
			return
		}
		runAs := &sudosocpb.RunAs{}
		err = proto.Unmarshal(task.Response, runAs)
		if err != nil {
			con.PrintErrorf("Failed to decode task request: %s\n", err)
			return
		}
		beacon, err := con.Rpc.GetBeacon(context.Background(), &clientpb.Beacon{ID: task.BeaconID})
		if err != nil {
			con.PrintErrorf("Failed to fetch beacon: %s\n", err)
			return
		}
		privilege.PrintRunAs(runAs, runAsReq.ProcessName, runAsReq.Args, beacon.Name, con)

	// ---------------------
	// Processes commands
	// ---------------------
	case sudosocpb.MsgProcessDumpReq:
		dump := &sudosocpb.ProcessDump{}
		err := proto.Unmarshal(task.Response, dump)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		promptSaveToFile(dump.Data, con)

	case sudosocpb.MsgPsReq:
		ps := &sudosocpb.Ps{}
		err := proto.Unmarshal(task.Response, ps)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		beacon, err := con.Rpc.GetBeacon(context.Background(), &clientpb.Beacon{ID: task.BeaconID})
		if err != nil {
			con.PrintErrorf("Failed to get beacon: %s\n", err)
			return
		}

		f := pflag.NewFlagSet("ps", pflag.ContinueOnError) // Create the flag set.
		f.IntP("pid", "p", -1, "filter based on pid")
		f.StringP("exe", "e", "", "filter based on executable name")
		f.StringP("owner", "o", "", "filter based on owner")
		f.BoolP("print-cmdline", "c", true, "print command line arguments")
		f.BoolP("overflow", "O", false, "overflow terminal width (display truncated rows)")
		f.IntP("skip-pages", "S", 0, "skip the first n page(s)")
		f.BoolP("tree", "T", false, "print process tree")
		f.BoolP("full", "f", false, "show full process info (owner, command line, session information, may trigger EDR), default true on all non-Windows OSs, false on Windows")

		fullInfo := beacon.OS != "windows"

		processes.PrintPS(beacon.OS, ps, true, fullInfo, f, con)

	case sudosocpb.MsgTerminateReq:
		terminate := &sudosocpb.Terminate{}
		err := proto.Unmarshal(task.Response, terminate)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		processes.PrintTerminate(terminate, con)

	// ---------------------
	// Registry commands
	// ---------------------
	case sudosocpb.MsgRegistryCreateKeyReq:
		createKeyReq := &sudosocpb.RegistryCreateKeyReq{}
		err := proto.Unmarshal(task.Request, createKeyReq)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		createKey := &sudosocpb.RegistryCreateKey{}
		err = proto.Unmarshal(task.Response, createKey)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		registry.PrintCreateKey(createKey, createKeyReq.Path, createKeyReq.Key, con)

	case sudosocpb.MsgRegistryDeleteKeyReq:
		deleteKeyReq := &sudosocpb.RegistryDeleteKeyReq{}
		err := proto.Unmarshal(task.Request, deleteKeyReq)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		deleteKey := &sudosocpb.RegistryDeleteKey{}
		err = proto.Unmarshal(task.Response, deleteKey)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		registry.PrintDeleteKey(deleteKey, deleteKeyReq.Path, deleteKeyReq.Key, con)

	case sudosocpb.MsgRegistryListValuesReq:
		listValuesReq := &sudosocpb.RegistryListValuesReq{}
		err := proto.Unmarshal(task.Request, listValuesReq)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		regList := &sudosocpb.RegistryValuesList{}
		err = proto.Unmarshal(task.Response, regList)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		registry.PrintListValues(regList, listValuesReq.Hive, listValuesReq.Path, con)

	case sudosocpb.MsgRegistrySubKeysListReq:
		listValuesReq := &sudosocpb.RegistrySubKeyListReq{}
		err := proto.Unmarshal(task.Request, listValuesReq)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		regList := &sudosocpb.RegistrySubKeyList{}
		err = proto.Unmarshal(task.Response, regList)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		registry.PrintListSubKeys(regList, listValuesReq.Hive, listValuesReq.Path, con)

	case sudosocpb.MsgRegistryReadReq:
		regRead := &sudosocpb.RegistryRead{}
		err := proto.Unmarshal(task.Response, regRead)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		registry.PrintRegRead(regRead, con)

	case sudosocpb.MsgRegistryWriteReq:
		regWrite := &sudosocpb.RegistryWrite{}
		err := proto.Unmarshal(task.Response, regWrite)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		registry.PrintRegWrite(regWrite, con)

	// ---------------------
	// Screenshot
	// ---------------------
	case sudosocpb.MsgScreenshotReq:
		screenshot := &sudosocpb.Screenshot{}
		err := proto.Unmarshal(task.Response, screenshot)
		if err != nil {
			con.PrintErrorf("Failed to decode task response: %s\n", err)
			return
		}
		promptSaveToFile(screenshot.Data, con)

	// ---------------------
	// Default
	// ---------------------
	default:
		con.PrintErrorf("Cannot render task response for msg type %v\n", reqEnvelope.Type)
	}
}

func taskResponseDownload(download *sudosocpb.Download, con *console.SudosocClient) {
	const (
		dump   = "Dump Contents"
		saveTo = "Save to File ..."
	)
	action := saveTo
	err := forms.SelectRequired("Choose an option:", []string{dump, saveTo}, &action)
	if err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}
	switch action {
	case dump:
		con.Printf("%s\n", string(download.Data))
	default:
		promptSaveToFile(download.Data, con)
	}
}

func promptSaveToFile(data []byte, con *console.SudosocClient) {
	saveTo := ""
	err := forms.Input("Save to:", &saveTo)
	if err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}
	if _, err := os.Stat(saveTo); !os.IsNotExist(err) {
		confirm := false
		_ = forms.Confirm("Overwrite existing file?", &confirm)
		if !confirm {
			return
		}
	}
	err = os.WriteFile(saveTo, data, 0o600)
	if err != nil {
		con.PrintErrorf("Failed to save file: %s\n", err)
		return
	}
	con.PrintInfof("Wrote %d byte(s) to %s", len(data), saveTo)
}
