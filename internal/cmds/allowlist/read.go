package allowlist

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/spf13/cobra"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func newListCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the current allowlist",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			c, err := o.client(ctx(cmd))
			if err != nil {
				return err
			}
			resp, err := c.List(ctx(cmd))
			if err != nil {
				return err
			}
			return printAllowlist(cmd.OutOrStdout(), o.output, resp)
		},
	}
}

func newExportCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "export [file]",
		Short: "Write the current allowlist to a file (default stdout) for backup or re-upload",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			c, err := o.client(ctx(cmd))
			if err != nil {
				return err
			}
			resp, err := c.List(ctx(cmd))
			if err != nil {
				return err
			}
			// Always the canonical allowlist JSON so the file round-trips with
			// `upload` and cds --allowlist-seed.
			data, err := json.MarshalIndent(resp, "", "  ")
			if err != nil {
				return err
			}
			data = append(data, '\n')

			if len(args) == 1 && args[0] != "-" {
				if err := os.WriteFile(args[0], data, 0o644); err != nil {
					return fmt.Errorf("write %q: %w", args[0], err)
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "wrote %d entries to %s\n", len(resp.Digests), args[0])
				return nil
			}
			_, err = cmd.OutOrStdout().Write(data)
			return err
		},
	}
}

func newDiffCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "diff <file>",
		Short: "Show how an allowlist file differs from the live allowlist",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			desired, err := loadAllowlistFile(args[0])
			if err != nil {
				return err
			}
			c, err := o.client(ctx(cmd))
			if err != nil {
				return err
			}
			resp, err := c.List(ctx(cmd))
			if err != nil {
				return err
			}
			d := computeDiff(toStringMap(resp.Digests), desired.Digests)
			return printDiff(cmd.OutOrStdout(), o.output, d)
		},
	}
}

// --- shared helpers ---

// loadAllowlistFile reads and validates an allowlist JSON file (version +
// digests map), the same format `export` writes and cds --allowlist-seed reads.
func loadAllowlistFile(path string) (*pkgallowlist.Allowlist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read allowlist file %q: %w", path, err)
	}
	wl, err := pkgallowlist.ParseJSON(data)
	if err != nil {
		return nil, fmt.Errorf("parse allowlist file %q: %w", path, err)
	}
	return wl, nil
}

func toStringMap(m map[types.Digest]string) map[string]string {
	out := make(map[string]string, len(m))
	for d, img := range m {
		out[d.String()] = img
	}
	return out
}

type changedEntry struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type diffResult struct {
	Added   map[string]string       `json:"added"`
	Removed map[string]string       `json:"removed"`
	Changed map[string]changedEntry `json:"changed"`
}

func (d diffResult) empty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0
}

// computeDiff reports what applying desired over current would change.
func computeDiff(current, desired map[string]string) diffResult {
	d := diffResult{
		Added:   map[string]string{},
		Removed: map[string]string{},
		Changed: map[string]changedEntry{},
	}
	for digest, image := range desired {
		cur, ok := current[digest]
		switch {
		case !ok:
			d.Added[digest] = image
		case cur != image:
			d.Changed[digest] = changedEntry{From: cur, To: image}
		}
	}
	for digest, image := range current {
		if _, ok := desired[digest]; !ok {
			d.Removed[digest] = image
		}
	}
	return d
}

func printAllowlist(w io.Writer, format string, resp types.AllowlistListResponse) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(resp)
	}
	images := toStringMap(resp.Digests)
	fmt.Fprintf(w, "version: %s (%d entries)\n", resp.Version, len(images))
	for _, digest := range sortedKeys(images) {
		fmt.Fprintf(w, "%s  %s\n", digest, images[digest])
	}
	return nil
}

func printDiff(w io.Writer, format string, d diffResult) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(d)
	}
	if d.empty() {
		fmt.Fprintln(w, "no changes")
		return nil
	}
	for _, digest := range sortedKeys(d.Added) {
		fmt.Fprintf(w, "+ %s  %s\n", digest, d.Added[digest])
	}
	for _, digest := range sortedKeys(d.Removed) {
		fmt.Fprintf(w, "- %s  %s\n", digest, d.Removed[digest])
	}
	changedKeys := make([]string, 0, len(d.Changed))
	for k := range d.Changed {
		changedKeys = append(changedKeys, k)
	}
	sort.Strings(changedKeys)
	for _, digest := range changedKeys {
		fmt.Fprintf(w, "~ %s  %s -> %s\n", digest, d.Changed[digest].From, d.Changed[digest].To)
	}
	return nil
}
