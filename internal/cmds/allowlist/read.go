package allowlist

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func newListCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the current allowlist floor and workload entries",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			al, version, err := o.fetch(ctx(cmd))
			if err != nil {
				return err
			}
			if o.output == "json" {
				return writeJSON(cmd.OutOrStdout(), al)
			}
			printAllowlistText(cmd.OutOrStdout(), al, version)
			return nil
		},
	}
}

func newExportCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "export [file]",
		Short: "Write the full allowlist as canonical JSON (default stdout) for backup or re-upload",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			al, _, err := o.fetch(ctx(cmd))
			if err != nil {
				return err
			}
			// Canonical bytes round-trip with `upload` and cds --allowlist-seed.
			data, err := al.Canonical()
			if err != nil {
				return err
			}
			data = append(data, '\n')

			if len(args) == 1 && args[0] != "-" {
				if err := os.WriteFile(args[0], data, 0o644); err != nil {
					return fmt.Errorf("write %q: %w", args[0], err)
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "wrote %d floor digest(s) and %d workload(s) to %s\n",
					len(al.Digests), len(al.Workloads), args[0])
				return nil
			}
			_, err = cmd.OutOrStdout().Write(data)
			return err
		},
	}
}

func newDiffCmd(o *options) *cobra.Command {
	var exitCode bool
	cmd := &cobra.Command{
		Use:   "diff <file>",
		Short: "Show how an allowlist file differs from the live allowlist",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			desired, err := loadAllowlistFile(args[0])
			if err != nil {
				return err
			}
			live, _, err := o.fetch(ctx(cmd))
			if err != nil {
				return err
			}
			d := diffAllowlists(live, desired)
			if err := printDiff(cmd.OutOrStdout(), o.output, d); err != nil {
				return err
			}
			if exitCode && !d.empty() {
				cmd.SilenceErrors = true
				return errDifferences
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&exitCode, "exit-code", false, "exit non-zero when the file and the live allowlist differ")
	return cmd
}

// errDifferences is the sentinel `diff --exit-code` returns when the file and
// the live allowlist differ; SilenceErrors keeps it from printing.
var errDifferences = fmt.Errorf("allowlist differs")

// --- shared helpers ---

// fetch builds the CDS client and returns the live allowlist and its version.
func (o *options) fetch(ctx context.Context) (*pkgallowlist.Allowlist, string, error) {
	if err := o.validate(); err != nil {
		return nil, "", err
	}
	c, err := o.client(ctx)
	if err != nil {
		return nil, "", err
	}
	return c.List(ctx)
}

// loadAllowlistFile reads and validates a full allowlist JSON file — the format
// `export` writes and cds --allowlist-seed reads.
func loadAllowlistFile(path string) (*pkgallowlist.Allowlist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read allowlist file %q: %w", path, err)
	}
	al, err := pkgallowlist.ParseJSON(data)
	if err != nil {
		return nil, fmt.Errorf("parse allowlist file %q: %w", path, err)
	}
	return al, nil
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// --- text rendering ---

func printAllowlistText(w io.Writer, al *pkgallowlist.Allowlist, version string) {
	fmt.Fprintf(w, "version %s: %d floor digest(s), %d workload(s)\n\n", version, len(al.Digests), len(al.Workloads))
	printFloorTable(w, al.Digests)
	fmt.Fprintln(w)
	printWorkloadTable(w, al.Workloads)
}

func printFloorTable(w io.Writer, digests map[string]string) {
	fmt.Fprintf(w, "floor (%d):\n", len(digests))
	if len(digests) == 0 {
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "DIGEST\tIMAGE")
	for _, d := range sortedKeys(digests) {
		fmt.Fprintf(tw, "%s\t%s\n", d, digests[d])
	}
	tw.Flush()
}

func printWorkloadTable(w io.Writer, workloads map[string]pkgallowlist.Workload) {
	fmt.Fprintf(w, "workloads (%d):\n", len(workloads))
	if len(workloads) == 0 {
		return
	}
	names := make([]string, 0, len(workloads))
	for name := range workloads {
		names = append(names, name)
	}
	sort.Strings(names)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tINIT\tCTRS\tENTRYPOINT/CMD\tPATHS")
	for _, name := range names {
		wl := workloads[name]
		ep, cmd, paths := summarizeWorkload(wl)
		fmt.Fprintf(tw, "%s\t%d\t%d\t%s\t%s\n", name, len(wl.InitContainers), len(wl.Containers),
			"ep="+ep+" cmd="+cmd, paths)
	}
	tw.Flush()
}

// summarizeWorkload aggregates the entrypoint policies, cmd policies, and path
// grant/deny counts across every container (init and main) in an entry.
func summarizeWorkload(w pkgallowlist.Workload) (ep, cmd, paths string) {
	epSet, cmdSet := map[string]bool{}, map[string]bool{}
	var readN, writeN, anyN int
	for _, c := range allContainers(w) {
		epSet[argvPolicyName(c.Entrypoint)] = true
		cmdSet[argvPolicyName(c.Cmd)] = true
		switch c.Paths.Policy {
		case pkgallowlist.PolicyAllow:
			readN += len(c.Paths.Read)
			writeN += len(c.Paths.Write)
		case pkgallowlist.PolicyAny:
			anyN++
		}
	}
	pathStr := fmt.Sprintf("R=%d W=%d", readN, writeN)
	if anyN > 0 {
		pathStr += fmt.Sprintf(" any=%d", anyN)
	}
	return joinSet(epSet), joinSet(cmdSet), pathStr
}

// allContainers returns the init containers followed by the main containers.
func allContainers(w pkgallowlist.Workload) []pkgallowlist.Container {
	out := make([]pkgallowlist.Container, 0, len(w.InitContainers)+len(w.Containers))
	out = append(out, w.InitContainers...)
	out = append(out, w.Containers...)
	return out
}

func argvPolicyName(p pkgallowlist.ArgvPolicy) string {
	if p.Policy == "" {
		return pkgallowlist.PolicyDeny
	}
	return p.Policy
}

func joinSet(set map[string]bool) string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := ""
	for i, k := range keys {
		if i > 0 {
			out += ","
		}
		out += k
	}
	return out
}

// argvSummary renders one argv policy for diff output.
func argvSummary(p pkgallowlist.ArgvPolicy) string {
	switch p.Policy {
	case pkgallowlist.PolicyExact:
		return "exact[" + shellJoin(p.Argv) + "]"
	case pkgallowlist.PolicyAny:
		return "any"
	default:
		return "deny"
	}
}

func pathSummary(p pkgallowlist.PathPolicy) string {
	switch p.Policy {
	case pkgallowlist.PolicyAny:
		return "any"
	case pkgallowlist.PolicyAllow:
		return fmt.Sprintf("allow(r=%d,w=%d)", len(p.Read), len(p.Write))
	default:
		return "deny"
	}
}

// containerSummary renders one container's policy triple, e.g.
// "ep=exact[/bin/sh -c] cmd=any paths=deny".
func containerSummary(c pkgallowlist.Container) string {
	return fmt.Sprintf("ep=%s cmd=%s paths=%s", argvSummary(c.Entrypoint), argvSummary(c.Cmd), pathSummary(c.Paths))
}

func shellJoin(argv []string) string {
	out := ""
	for i, a := range argv {
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out
}
