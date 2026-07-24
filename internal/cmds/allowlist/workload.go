package allowlist

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
)

func newWorkloadCmd(o *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workload",
		Short: "Manage named workload policy entries",
		Long: `Workload entries pin an init/main container set; each container carries a
command/args (argv) and path policy that is enforced by container digest, not
by name or image ref.`,
	}
	cmd.AddCommand(
		newWorkloadListCmd(o),
		newWorkloadGetCmd(o),
		newWorkloadApplyCmd(o),
		newWorkloadEditCmd(o),
		newWorkloadDeleteCmd(o),
	)
	return cmd
}

func newWorkloadListCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List workload entries",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			al, _, err := o.fetch(ctx(cmd))
			if err != nil {
				return err
			}
			if o.output == "json" {
				return writeJSON(cmd.OutOrStdout(), al.Workloads)
			}
			printWorkloadTable(cmd.OutOrStdout(), al.Workloads)
			return nil
		},
	}
}

func newWorkloadGetCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "get <name>",
		Short: "Print one workload entry as canonical JSON",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			al, _, err := o.fetch(ctx(cmd))
			if err != nil {
				return err
			}
			w, ok := al.Workloads[args[0]]
			if !ok {
				return fmt.Errorf("no workload entry named %q", args[0])
			}
			return writeJSON(cmd.OutOrStdout(), w)
		},
	}
}

func newWorkloadApplyCmd(o *options) *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "apply <file|->",
		Short: "Upsert workload entries from a file (whole-entry replace)",
		Long: `Upsert each workload entry in <file> (or stdin with '-'). The file is either a
full/partial allowlist document or a name-keyed map of workload entries. Each
entry is replaced whole — this never field-merges into a live entry. Floor
digests in the file are ignored; use 'upload' or 'add'.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			data, err := readFileOrStdin(cmd, args[0])
			if err != nil {
				return err
			}
			entries, ignoredFloor, err := parseWorkloadEntries(data)
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				return fmt.Errorf("no workload entries in %q", args[0])
			}
			if ignoredFloor > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "note: %d floor digest(s) in the file are ignored by 'workload apply'; use 'upload' or 'add'\n", ignoredFloor)
			}

			for _, wmsg := range lintOffline(&pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: entries}) {
				fmt.Fprintf(cmd.ErrOrStderr(), "lint: %s\n", wmsg)
			}

			c, err := o.client(ctx(cmd))
			if err != nil {
				return err
			}
			live, _, err := c.List(ctx(cmd))
			if err != nil {
				return err
			}

			names := sortedWorkloadNames(entries)
			for _, name := range names {
				if lw, ok := live.Workloads[name]; ok {
					ed := diffEntry(lw, entries[name])
					if ed.empty() {
						fmt.Fprintf(cmd.OutOrStdout(), "= %s (unchanged)\n", name)
						continue
					}
					fmt.Fprintf(cmd.OutOrStdout(), "~ %s\n", name)
					printEntryDiff(cmd.OutOrStdout(), ed)
				} else {
					fmt.Fprintf(cmd.OutOrStdout(), "+ %s (new)\n", name)
				}
			}

			if dryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "dry-run: would upsert %d workload entr(ies)\n", len(entries))
				return nil
			}
			signer, err := o.signer()
			if err != nil {
				return err
			}
			for _, name := range names {
				if err := c.PutWorkload(ctx(cmd), name, entries[name], signer); err != nil {
					return fmt.Errorf("put workload %q: %w", name, err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "applied %s\n", name)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show the diff without writing any entry")
	return cmd
}

func newWorkloadEditCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "edit <name>",
		Short: "Fetch a workload entry, edit it in $EDITOR, and apply the result",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			name := args[0]
			c, err := o.client(ctx(cmd))
			if err != nil {
				return err
			}
			live, _, err := c.List(ctx(cmd))
			if err != nil {
				return err
			}
			orig, ok := live.Workloads[name]
			if !ok {
				return fmt.Errorf("no workload entry named %q", name)
			}

			edited, err := editWorkloadInEditor(orig, name)
			if err != nil {
				return err
			}
			if diffEntry(orig, *edited).empty() {
				fmt.Fprintln(cmd.ErrOrStderr(), "no changes")
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "~ %s\n", name)
			printEntryDiff(cmd.OutOrStdout(), diffEntry(orig, *edited))

			if !confirm(cmd, fmt.Sprintf("apply changes to %q?", name)) {
				fmt.Fprintln(cmd.ErrOrStderr(), "aborted")
				return nil
			}
			signer, err := o.signer()
			if err != nil {
				return err
			}
			if err := c.PutWorkload(ctx(cmd), name, *edited, signer); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "applied %s\n", name)
			return nil
		},
	}
}

func newWorkloadDeleteCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name> [<name>...]",
		Short: "Delete one or more workload entries",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			signer, err := o.signer()
			if err != nil {
				return err
			}
			c, err := o.client(ctx(cmd))
			if err != nil {
				return err
			}
			for _, name := range args {
				if err := c.DeleteWorkload(ctx(cmd), name, signer); err != nil {
					var se *allowlistclient.StatusError
					if errors.As(err, &se) && se.Status == 404 {
						return fmt.Errorf("no workload entry named %q", name)
					}
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "deleted %s\n", name)
			}
			return nil
		},
	}
}

// --- shared helpers ---

// parseWorkloadEntries accepts either a full/partial allowlist document or a
// bare name-keyed map of workload entries, returning the entries and the count
// of floor digests it ignored (nonzero only for an allowlist document).
func parseWorkloadEntries(data []byte) (entries map[string]pkgallowlist.Workload, ignoredFloor int, err error) {
	if al, perr := pkgallowlist.ParseJSON(data); perr == nil {
		if al.Workloads == nil {
			al.Workloads = map[string]pkgallowlist.Workload{}
		}
		return al.Workloads, len(al.Digests), nil
	}

	var raw map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if derr := dec.Decode(&raw); derr != nil {
		return nil, 0, fmt.Errorf("parse workload entries: not an allowlist document or a name-keyed workload map: %w", derr)
	}
	out := make(map[string]pkgallowlist.Workload, len(raw))
	for name, body := range raw {
		w, werr := pkgallowlist.ParseWorkloadJSON(body)
		if werr != nil {
			return nil, 0, fmt.Errorf("workload %q: %w", name, werr)
		}
		out[name] = *w
	}
	return out, 0, nil
}

func sortedWorkloadNames(m map[string]pkgallowlist.Workload) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func readFileOrStdin(cmd *cobra.Command, path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(cmd.InOrStdin())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	return data, nil
}

// editWorkloadInEditor writes the entry to a temp file, opens $EDITOR (vi if
// unset) on it, and re-validates the result via ParseWorkloadJSON.
func editWorkloadInEditor(w pkgallowlist.Workload, name string) (*pkgallowlist.Workload, error) {
	tmp, err := os.CreateTemp("", "c8s-workload-"+sanitizeFileName(name)+"-*.json")
	if err != nil {
		return nil, err
	}
	path := tmp.Name()
	defer os.Remove(path)

	data, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		tmp.Close()
		return nil, err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return nil, err
	}
	tmp.Close()

	if err := runEditor(path); err != nil {
		return nil, err
	}
	edited, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return pkgallowlist.ParseWorkloadJSON(edited)
}

func runEditor(path string) error {
	editor := os.Getenv("EDITOR")
	if strings.TrimSpace(editor) == "" {
		editor = "vi"
	}
	fields := strings.Fields(editor)
	args := append(fields[1:], path)
	c := exec.Command(fields[0], args...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("editor %q: %w", editor, err)
	}
	return nil
}

func sanitizeFileName(name string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, name)
}

func confirm(cmd *cobra.Command, prompt string) bool {
	fmt.Fprintf(cmd.ErrOrStderr(), "%s [y/N] ", prompt)
	line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}
