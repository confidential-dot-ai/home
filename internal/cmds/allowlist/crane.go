package allowlist

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// requireCrane fails with actionable guidance when the crane CLI is not on
// PATH, so a missing binary surfaces as an install hint rather than an opaque
// exec error from the first crane call.
func requireCrane() error {
	if _, err := exec.LookPath("crane"); err != nil {
		return fmt.Errorf("this command needs the 'crane' CLI on PATH (github.com/google/go-containerregistry); install it and retry")
	}
	return nil
}

// craneDigest resolves an image reference to its registry digest via
// `crane digest <ref>`. crane handles registry auth, manifest lists, and the
// registry HTTP protocol. The returned value is a bare "sha256:<hex>".
func craneDigest(ctx context.Context, ref string) (string, error) {
	out, err := exec.CommandContext(ctx, "crane", "digest", ref).Output()
	if err != nil {
		return "", craneError("digest", ref, err)
	}
	digest := strings.TrimSpace(string(out))
	if !strings.HasPrefix(digest, "sha256:") {
		return "", fmt.Errorf("crane digest %q returned unexpected value %q", ref, digest)
	}
	return digest, nil
}

// craneConfig returns the parsed OCI image config for a reference via
// `crane config <ref>`, exposing the image's baked Entrypoint and Cmd.
func craneConfig(ctx context.Context, ref string) (*imageConfig, error) {
	out, err := exec.CommandContext(ctx, "crane", "config", ref).Output()
	if err != nil {
		return nil, craneError("config", ref, err)
	}
	var cfg imageConfig
	if err := json.Unmarshal(out, &cfg); err != nil {
		return nil, fmt.Errorf("parse crane config %q: %w", ref, err)
	}
	return &cfg, nil
}

// craneManifestExists reports whether a specific digest is resolvable in its
// repository via `crane manifest <repo>@<digest>`.
func craneManifestExists(ctx context.Context, ref string) error {
	if err := exec.CommandContext(ctx, "crane", "manifest", ref).Run(); err != nil {
		return craneError("manifest", ref, err)
	}
	return nil
}

// imageConfig is the subset of an OCI image config the CLI reads.
type imageConfig struct {
	Config struct {
		Entrypoint []string `json:"Entrypoint"`
		Cmd        []string `json:"Cmd"`
	} `json:"config"`
}

func craneError(sub, ref string, err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return fmt.Errorf("crane %s %q: %w: %s", sub, ref, err, strings.TrimSpace(string(ee.Stderr)))
	}
	return fmt.Errorf("crane %s %q: %w", sub, ref, err)
}
