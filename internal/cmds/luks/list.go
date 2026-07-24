package luks

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func newListCmd() *cobra.Command {
	var (
		bf       baoFlags
		workload string
		output   string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List openbao-gated LUKS volumes for a workload",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := bf.client()
			if err != nil {
				return err
			}
			return runList(cmd.Context(), c, workload, output)
		},
	}
	bf.bind(cmd)
	cmd.Flags().StringVar(&workload, "workload", "", "confidential.ai/cw workload id (required)")
	cmd.Flags().StringVar(&output, "output", "table", "output format: table | yaml | json")
	return cmd
}

func runList(ctx context.Context, c *bao, workload, output string) error {
	if err := validateWorkload(workload); err != nil {
		return err
	}
	names, err := c.listVolumes(ctx, workload)
	if err != nil {
		return fmt.Errorf("list volumes: %w", err)
	}
	switch output {
	case "table":
		if len(names) == 0 {
			fmt.Println("(no LUKS volumes for workload", workload+")")
			return nil
		}
		fmt.Printf("%-30s %s\n", "NAME", "KV PATH")
		for _, n := range names {
			fmt.Printf("%-30s secret/data/%s/luks-%s\n", n, workload, n)
		}
		return nil
	case "yaml":
		return yaml.NewEncoder(os.Stdout).Encode(map[string]any{
			"workload": workload, "volumes": names,
		})
	case "json":
		return jsonEncoder().Encode(map[string]any{
			"workload": workload, "volumes": names,
		})
	}
	return fmt.Errorf("--output %q: want table | yaml | json", output)
}
