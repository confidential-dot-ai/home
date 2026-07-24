package luks

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func newShowCmd() *cobra.Command {
	var (
		bf             baoFlags
		workload, name string
		output         string
	)
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show openbao metadata for a LUKS volume (no passphrase disclosure)",
		Long: "show reads the KV metadata (create/modify time, version count) " +
			"for the named volume WITHOUT disclosing its passphrase. Use to " +
			"confirm a volume was successfully created, or to spot drift " +
			"between the KV entry and a workload's expectations.",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := bf.client()
			if err != nil {
				return err
			}
			return runShow(cmd.Context(), c, workload, name, output)
		},
	}
	bf.bind(cmd)
	cmd.Flags().StringVar(&workload, "workload", "", "confidential.ai/cw workload id (required)")
	cmd.Flags().StringVar(&name, "name", "", "volume name (required)")
	cmd.Flags().StringVar(&output, "output", "yaml", "output format: yaml | json")
	return cmd
}

func runShow(ctx context.Context, c *bao, workload, name, output string) error {
	if err := validateWorkloadName(workload, name); err != nil {
		return err
	}
	meta, err := c.readMetadata(ctx, workload, name)
	if err != nil {
		if isNotFound(err) {
			return fmt.Errorf("no LUKS volume %q for workload %q", name, workload)
		}
		return err
	}
	out := map[string]any{
		"workload": workload,
		"name":     name,
		"kv_path":  "secret/data/" + workload + "/luks-" + name,
		"metadata": meta,
	}
	switch output {
	case "yaml":
		return yaml.NewEncoder(os.Stdout).Encode(out)
	case "json":
		return jsonEncoder().Encode(out)
	}
	return fmt.Errorf("--output %q: want yaml or json", output)
}
