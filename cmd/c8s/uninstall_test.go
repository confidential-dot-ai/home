//go:build !c8s_node

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/lunal-dev/c8s/internal/helmchart"
)

func TestBuildHelmUninstallArgs(t *testing.T) {
	got := buildHelmUninstallArgs("c8s", "c8s-system", true)
	assertArgsEqual(t, got, []string{
		"uninstall", "c8s", "--namespace", "c8s-system", "--wait", "--timeout=5m",
	})

	got = buildHelmUninstallArgs("c8s", "c8s-system", false)
	assertArgsEqual(t, got, []string{"uninstall", "c8s", "--namespace", "c8s-system"})
}

// --host-sweep-only exists only to run the sweep, so combining it with
// --kata-sweep=false asks for nothing and must error rather than silently
// no-op.
func TestValidateUninstallFlagsRejectsSweepOnlyWithoutSweep(t *testing.T) {
	if err := validateUninstallFlags(false, true); err == nil {
		t.Fatal("--host-sweep-only with --kata-sweep=false: want error, got nil")
	}
	for _, tc := range []struct{ kataSweep, hostSweepOnly bool }{
		{true, true}, {true, false}, {false, false},
	} {
		if err := validateUninstallFlags(tc.kataSweep, tc.hostSweepOnly); err != nil {
			t.Errorf("kataSweep=%t hostSweepOnly=%t: unexpected error: %v", tc.kataSweep, tc.hostSweepOnly, err)
		}
	}
}

// The running-pod guard must catch every kata RuntimeClass the chart renders
// and nothing else — runc pods (empty class) and non-kata classes (gvisor)
// are unaffected by a kata uninstall.
func TestFilterKataPodsKeepsOnlyKataRuntimeClasses(t *testing.T) {
	lines := []string{
		"default\tinference-0\tkata-qemu-snp",
		"default\tweb-0\t", // no runtimeClassName (runc)
		"team-a\tbatch-1\tkata-qemu",
		"team-b\tsandbox-2\tgvisor", // non-kata RuntimeClass
		"team-c\tclh-0\tkata-clh",
		"", // trailing blank line from kubectl
		"malformed-line-no-tabs",
	}
	got := filterKataPods(lines)
	want := []string{
		"default/inference-0 (kata-qemu-snp)",
		"team-a/batch-1 (kata-qemu)",
		"team-c/clh-0 (kata-clh)",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("filterKataPods = %v, want %v", got, want)
	}
}

// The sweep must target exactly the directory the install wrote into — the
// same mapping as the chart's c8s.kataContainerdConfigDir helper.
func TestKataContainerdDir(t *testing.T) {
	tests := []struct {
		name     string
		override string
		distro   string
		want     string
		wantErr  bool
	}{
		{name: "k8s", distro: "k8s", want: "/etc/containerd"},
		{name: "rke2", distro: "rke2", want: "/var/lib/rancher/rke2/agent/etc/containerd"},
		{name: "override wins over distro", override: "/etc/k0s/containerd.d", distro: "rke2", want: "/etc/k0s/containerd.d"},
		// An unknown distro with no override has no safe directory to sweep;
		// guessing would rm -rf the wrong place or silently miss the files.
		{name: "unknown distro fails", distro: "k3s", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := kataContainerdDir(tt.override, tt.distro)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %t", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("dir = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestKataRestartCommandPerDistro(t *testing.T) {
	// RKE2 owns containerd inside its server/agent unit, so a bare containerd
	// restart there would not re-read the config.
	rke2 := kataRestartCommand("rke2")
	for _, unit := range []string{"rke2-server", "rke2-agent"} {
		if !strings.Contains(rke2, unit) {
			t.Errorf("rke2 restart command %q missing unit %q", rke2, unit)
		}
	}
	if got := kataRestartCommand("k8s"); got != "systemctl restart containerd" {
		t.Errorf("k8s restart command = %q, want plain containerd restart", got)
	}
}

// chartValuesTree decodes a YAML values document the way the uninstall reads
// helm output into a values tree.
func chartValuesTree(t *testing.T, doc string) map[string]any {
	t.Helper()
	var tree map[string]any
	if err := yaml.Unmarshal([]byte(doc), &tree); err != nil {
		t.Fatalf("unmarshal test values: %v", err)
	}
	return tree
}

func TestKataConfigFromValues(t *testing.T) {
	tree := chartValuesTree(t, `
kata:
  enabled: true
  distro: rke2
  containerdConfigDir: ""
  nodeSelector:
    confidential.ai/kata: "true"
  containerdPrep:
    image:
      repository: busybox
      tag: ""
      digest: "sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028"
  guestImage:
    hostPath: /var/lib/c8s/kata-images
`)
	cfg, err := kataConfigFromValues(tree)
	if err != nil {
		t.Fatalf("kataConfigFromValues: %v", err)
	}
	want := kataUninstallConfig{
		Enabled:             true,
		Distro:              "rke2",
		ContainerdConfigDir: "/var/lib/rancher/rke2/agent/etc/containerd",
		GuestImageHostPath:  "/var/lib/c8s/kata-images",
		SweepImage:          "busybox@sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028",
		NodeSelector:        map[string]string{"confidential.ai/kata": "true"},
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("config = %+v, want %+v", cfg, want)
	}
}

// A non-kata install must come back Enabled=false (the sweep is skipped), and
// the rest of the config must still parse — --host-sweep-only sweeps with it.
func TestKataConfigFromValuesKataDisabled(t *testing.T) {
	tree := chartValuesTree(t, `
kata:
  enabled: false
  distro: k8s
  containerdConfigDir: ""
  containerdPrep:
    image:
      repository: busybox
      tag: "1.37"
      digest: ""
  guestImage:
    hostPath: /var/lib/c8s/kata-images
`)
	cfg, err := kataConfigFromValues(tree)
	if err != nil {
		t.Fatalf("kataConfigFromValues: %v", err)
	}
	if cfg.Enabled {
		t.Error("Enabled = true, want false")
	}
	if cfg.ContainerdConfigDir != "/etc/containerd" {
		t.Errorf("ContainerdConfigDir = %q, want /etc/containerd", cfg.ContainerdConfigDir)
	}
	// Digest empty → tag fallback.
	if cfg.SweepImage != "busybox:1.37" {
		t.Errorf("SweepImage = %q, want busybox:1.37", cfg.SweepImage)
	}
}

// Values without a kata block mean the release isn't the c8s chart; sweeping
// host paths based on guesses must fail loudly instead.
func TestKataConfigFromValuesRejectsForeignChart(t *testing.T) {
	if _, err := kataConfigFromValues(chartValuesTree(t, `foo: {bar: 1}`)); err == nil {
		t.Fatal("values without a kata block: want error, got nil")
	}
}

// The sweep config must parse out of the real embedded chart's values — the
// uninstall reads them via `helm get values --all` (computed from these
// defaults) and via `helm show values` on the --host-sweep-only path, so a
// renamed or removed values key would silently break the sweep. Mirrors
// TestChartComponentsFromValues.
func TestKataConfigFromEmbeddedChartValues(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not on PATH")
	}
	dir, err := extractChart()
	if err != nil {
		t.Fatalf("extractChart: %v", err)
	}
	defer os.RemoveAll(dir)

	out, err := exec.CommandContext(context.Background(), "helm", "show", "values",
		filepath.Join(dir, helmchart.ChartRoot)).Output()
	if err != nil {
		t.Fatalf("helm show values: %v", err)
	}
	cfg, err := kataConfigFromValues(chartValuesTree(t, string(out)))
	if err != nil {
		t.Fatalf("kataConfigFromValues on embedded chart defaults: %v", err)
	}
	if cfg.Enabled {
		t.Error("chart default kata.enabled = true, want false")
	}
	if cfg.ContainerdConfigDir != "/etc/containerd" {
		t.Errorf("ContainerdConfigDir = %q, want /etc/containerd (chart default distro k8s)", cfg.ContainerdConfigDir)
	}
	if cfg.GuestImageHostPath == "" {
		t.Error("GuestImageHostPath is empty")
	}
	// The chart digest-pins the containerd-prep image; the sweep must inherit
	// the pin, never a floating tag.
	if !strings.Contains(cfg.SweepImage, "@sha256:") {
		t.Errorf("SweepImage = %q, want a digest-pinned reference", cfg.SweepImage)
	}
}

func TestSweepImageRefRequiresPin(t *testing.T) {
	// Neither digest nor tag — never fall back to a floating default for a
	// privileged image with the host root mounted.
	tree := chartValuesTree(t, `
kata:
  containerdPrep:
    image:
      repository: busybox
      tag: ""
      digest: ""
`)
	if _, err := sweepImageRef(tree); err == nil {
		t.Fatal("unpinned containerdPrep image: want error, got nil")
	}
}

func TestKataSweepDaemonSetShape(t *testing.T) {
	cfg := kataUninstallConfig{
		Enabled:             true,
		Distro:              "rke2",
		ContainerdConfigDir: "/var/lib/rancher/rke2/agent/etc/containerd",
		GuestImageHostPath:  "/var/lib/c8s/kata-images",
		SweepImage:          "busybox@sha256:abc",
		NodeSelector:        map[string]string{"confidential.ai/kata": "true"},
	}
	ds := kataSweepDaemonSet("c8s", "c8s-system", cfg)

	if ds.Name != "c8s-kata-sweep" || ds.Namespace != "c8s-system" {
		t.Errorf("metadata = %s/%s, want c8s-system/c8s-kata-sweep", ds.Namespace, ds.Name)
	}

	pod := ds.Spec.Template.Spec
	// The sweep must reach every node kata-deploy installed on: the merged
	// linux + kata.nodeSelector node set, tolerating all taints, with hostPID
	// for the nsenter-driven runtime restart.
	wantSelector := map[string]string{
		"kubernetes.io/os":     "linux",
		"confidential.ai/kata": "true",
	}
	if !reflect.DeepEqual(pod.NodeSelector, wantSelector) {
		t.Errorf("nodeSelector = %v, want %v", pod.NodeSelector, wantSelector)
	}
	if len(pod.Tolerations) != 1 || pod.Tolerations[0].Operator != "Exists" {
		t.Errorf("tolerations = %v, want a single operator:Exists", pod.Tolerations)
	}
	if !pod.HostPID {
		t.Error("hostPID = false, want true")
	}

	if len(pod.InitContainers) != 1 {
		t.Fatalf("init containers = %d, want 1", len(pod.InitContainers))
	}
	sweep := pod.InitContainers[0]
	if sweep.SecurityContext == nil || sweep.SecurityContext.Privileged == nil || !*sweep.SecurityContext.Privileged {
		t.Error("sweep container is not privileged; it cannot touch the host paths")
	}
	if sweep.Image != cfg.SweepImage {
		t.Errorf("sweep image = %q, want %q", sweep.Image, cfg.SweepImage)
	}
	if len(sweep.Args) != 1 || sweep.Args[0] != kataSweepScript {
		t.Error("sweep container args do not carry the embedded kata-sweep.sh")
	}
	// The script's env contract (see kata-sweep.sh header) — every value the
	// release config carries must be plumbed.
	wantEnv := map[string]string{
		"HOST_CONTAINERD_DIR": "/var/lib/rancher/rke2/agent/etc/containerd",
		"GUEST_IMAGE_DIR":     "/var/lib/c8s/kata-images",
		"RKE2_PREP":           "true",
		"RESTART_COMMAND":     kataRestartCommand("rke2"),
	}
	gotEnv := map[string]string{}
	for _, e := range sweep.Env {
		gotEnv[e.Name] = e.Value
	}
	if !reflect.DeepEqual(gotEnv, wantEnv) {
		t.Errorf("sweep env = %v, want %v", gotEnv, wantEnv)
	}

	// The host root must be mounted where the script expects it.
	if len(pod.Volumes) != 1 || pod.Volumes[0].HostPath == nil || pod.Volumes[0].HostPath.Path != "/" {
		t.Errorf("volumes = %v, want a single hostPath /", pod.Volumes)
	}
	if len(sweep.VolumeMounts) != 1 || sweep.VolumeMounts[0].MountPath != "/host" {
		t.Errorf("sweep volume mounts = %v, want /host", sweep.VolumeMounts)
	}

	// Selector must match the template labels or the DaemonSet is rejected.
	if !reflect.DeepEqual(ds.Spec.Selector.MatchLabels, ds.Spec.Template.Labels) {
		t.Errorf("selector %v does not match template labels %v", ds.Spec.Selector.MatchLabels, ds.Spec.Template.Labels)
	}
}

// On a non-RKE2 distro the sweep must not touch the RKE2 prep template.
func TestKataSweepDaemonSetK8sDisablesRKE2Prep(t *testing.T) {
	ds := kataSweepDaemonSet("c8s", "c8s-system", kataUninstallConfig{
		Distro:              "k8s",
		ContainerdConfigDir: "/etc/containerd",
		GuestImageHostPath:  "/var/lib/c8s/kata-images",
		SweepImage:          "busybox@sha256:abc",
	})
	for _, e := range ds.Spec.Template.Spec.InitContainers[0].Env {
		if e.Name == "RKE2_PREP" && e.Value != "false" {
			t.Errorf("RKE2_PREP = %q on k8s, want false", e.Value)
		}
	}
}
