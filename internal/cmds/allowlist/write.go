package allowlist

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func newAddCmd(o *options) *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "add <digest> <image>",
		Short: "Add a single image digest to the allowlist",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			digest, err := types.ParseDigest(args[0])
			if err != nil {
				return err
			}
			image := args[1]

			if dryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "would add %s -> %s\n", digest, image)
				return nil
			}
			signer, err := o.signer()
			if err != nil {
				return err
			}
			c, err := o.client(ctx(cmd))
			if err != nil {
				return err
			}
			if err := c.Add(ctx(cmd), digest, image, signer); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "added %s\n", digest)
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the intended change without calling CDS")
	return cmd
}

func newRemoveCmd(o *options) *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "remove <digest> [<digest>...]",
		Short: "Remove one or more image digests from the allowlist",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			digests := make([]types.Digest, 0, len(args))
			for _, a := range args {
				d, err := types.ParseDigest(a)
				if err != nil {
					return err
				}
				digests = append(digests, d)
			}

			if dryRun {
				for _, d := range digests {
					fmt.Fprintf(cmd.OutOrStdout(), "would remove %s\n", d)
				}
				return nil
			}
			signer, err := o.signer()
			if err != nil {
				return err
			}
			c, err := o.client(ctx(cmd))
			if err != nil {
				return err
			}
			if err := c.Delete(ctx(cmd), digests, signer); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed %d digest(s)\n", len(digests))
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the intended change without calling CDS")
	return cmd
}

func newUploadCmd(o *options) *cobra.Command {
	var (
		dryRun   bool
		force    bool
		required []string
	)
	cmd := &cobra.Command{
		Use:   "upload <file>",
		Short: "Replace the entire allowlist with the contents of a file",
		Long: `Atomically replace the entire allowlist with the digests in <file>
(the format 'export' writes: {"version":..,"digests":{...}}). CDS assigns the
new version.

If the file names none of the core c8s components (` + fmt.Sprintf("%v", defaultRequiredComponents) + `),
upload refuses unless --force, since a cluster missing them cannot pull its own
control plane. Override the required set with --require.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			desired, err := loadAllowlistFile(args[0])
			if err != nil {
				return err
			}

			reqComponents := defaultRequiredComponents
			if len(required) > 0 {
				reqComponents = required
			}
			if missing := missingComponents(desired.Digests, reqComponents); len(missing) > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"warning: uploaded allowlist is missing core c8s component(s): %v\n", missing)
				if !force {
					return fmt.Errorf("refusing to upload an allowlist missing core components %v; re-run with --force if this is intentional", missing)
				}
				fmt.Fprintln(cmd.ErrOrStderr(), "proceeding anyway (--force)")
			}

			// Convert to the typed digest map the client sends.
			digests := make(map[types.Digest]string, len(desired.Digests))
			for ds, image := range desired.Digests {
				d, err := types.ParseDigest(ds)
				if err != nil {
					return fmt.Errorf("digest %q: %w", ds, err)
				}
				digests[d] = image
			}

			c, err := o.client(ctx(cmd))
			if err != nil {
				return err
			}

			// Show the operator what will change before writing.
			if resp, err := c.List(ctx(cmd)); err == nil {
				_ = printDiff(cmd.OutOrStdout(), o.output, computeDiff(toStringMap(resp.Digests), desired.Digests))
			} else {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not fetch current allowlist for diff: %v\n", err)
			}

			if dryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "dry-run: would replace allowlist with %d entries\n", len(digests))
				return nil
			}
			signer, err := o.signer()
			if err != nil {
				return err
			}
			if err := c.Replace(ctx(cmd), digests, signer); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "uploaded %d entries\n", len(digests))
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show the diff without replacing the allowlist")
	cmd.Flags().BoolVar(&force, "force", false, "upload even if core c8s components are missing")
	cmd.Flags().StringSliceVar(&required, "require", nil, "component identifiers that must appear in the uploaded image refs (overrides the default set)")
	return cmd
}
