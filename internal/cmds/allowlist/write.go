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
		Short: "Add a single image digest to the floor",
		Long: `Add one digest to the allowlist floor. A floor digest is admitted by digest
alone, regardless of argv — use it for standalone/injected component images, not
for pinning a workload's process policy (see 'allowlist workload').`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			digest, err := types.ParseDigest(args[0])
			if err != nil {
				return err
			}
			image, err := requireLabel(args[1], "image")
			if err != nil {
				return err
			}

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
			if err := c.AddDigest(ctx(cmd), digest, image, signer); err != nil {
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
		Short: "Remove one or more image digests from the floor",
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

			// Resolve the digests' image refs before deleting, so we can flag any
			// that are c8s component floor images: removing those from CDS does
			// not lock them out — the NRI plugin always_allow and the in-guest
			// baked seed keep admitting them — so a bare "removed" is misleading.
			served := map[string]string{}
			if live, _, err := c.List(ctx(cmd)); err == nil {
				served = live.Digests
			} else {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not fetch allowlist to check for component floor images: %v\n", err)
			}

			if err := c.DeleteDigests(ctx(cmd), digests, signer); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed %d digest(s)\n", len(digests))

			for _, d := range digests {
				if len(matchedComponents(served[d.String()], defaultRequiredComponents)) == 0 {
					continue
				}
				fmt.Fprintf(cmd.ErrOrStderr(),
					"warning: %s (%s) is a c8s component floor image; removing it from CDS does not lock it out — "+
						"the NRI plugin always_allow and the in-guest baked seed still admit it. "+
						"To block a compromised component image, roll the chart with the bad digest replaced.\n",
					d, served[d.String()])
			}
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
		strict   bool
		required []string
	)
	cmd := &cobra.Command{
		Use:   "upload <file>",
		Short: "Replace the entire allowlist (floor and workloads) with the contents of a file",
		Long: `Atomically replace the entire allowlist — floor digests and workload entries —
with the contents of <file> (the canonical JSON 'export' writes). CDS assigns the
new version.

If none of the file's image labels name a core c8s component (` + fmt.Sprintf("%v", defaultRequiredComponents) + `),
upload refuses unless --force, since a cluster missing them cannot pull its own
control plane. Override the required set with --require. The file is lint-checked
before upload; --strict makes lint warnings fatal.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			desired, err := loadAllowlistFile(args[0])
			if err != nil {
				return err
			}

			warnings := lintOffline(desired)
			for _, wmsg := range warnings {
				fmt.Fprintf(cmd.ErrOrStderr(), "lint: %s\n", wmsg)
			}
			if strict && len(warnings) > 0 {
				return fmt.Errorf("refusing to upload: %d lint warning(s) with --strict", len(warnings))
			}

			reqComponents := defaultRequiredComponents
			if len(required) > 0 {
				// An empty needle matches every ref and would silently disable the
				// guard; reject it (and a bare wildcard) outright.
				for _, r := range required {
					if _, err := requireLabel(r, "--require value"); err != nil {
						return err
					}
				}
				reqComponents = required
			}
			if missing := missingComponents(uploadImageLabels(desired), reqComponents); len(missing) > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"warning: uploaded allowlist is missing core c8s component(s): %v\n", missing)
				if !force {
					return fmt.Errorf("refusing to upload an allowlist missing core components %v; re-run with --force if this is intentional", missing)
				}
				fmt.Fprintln(cmd.ErrOrStderr(), "proceeding anyway (--force)")
			}

			c, err := o.client(ctx(cmd))
			if err != nil {
				return err
			}

			// Show the operator what will change before writing.
			if live, _, err := c.List(ctx(cmd)); err == nil {
				_ = printDiff(cmd.OutOrStdout(), o.output, diffAllowlists(live, desired))
			} else {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not fetch current allowlist for diff: %v\n", err)
			}

			if dryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "dry-run: would replace allowlist with %d floor digest(s) and %d workload(s)\n",
					len(desired.Digests), len(desired.Workloads))
				return nil
			}
			signer, err := o.signer()
			if err != nil {
				return err
			}
			if err := c.ReplaceAll(ctx(cmd), desired, signer); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "uploaded %d floor digest(s) and %d workload(s)\n",
				len(desired.Digests), len(desired.Workloads))
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show the diff without replacing the allowlist")
	cmd.Flags().BoolVar(&force, "force", false, "upload even if core c8s components are missing")
	cmd.Flags().BoolVar(&strict, "strict", false, "treat lint warnings as fatal")
	cmd.Flags().StringSliceVar(&required, "require", nil, "component identifiers that must appear in the uploaded image refs (overrides the default set)")
	return cmd
}

// requireLabel rejects an empty or bare-wildcard label. Image and name labels
// are informational, but "" or "*" almost always signals a mistake and a
// wildcard must never be mistaken for a policy value.
func requireLabel(val, what string) (string, error) {
	switch val {
	case "":
		return "", fmt.Errorf("%s must not be empty", what)
	case "*":
		return "", fmt.Errorf("%s must not be a bare wildcard %q", what, val)
	}
	return val, nil
}
