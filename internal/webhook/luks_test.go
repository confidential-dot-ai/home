package webhook

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestParseLUKSValueDefaults(t *testing.T) {
	lv, err := parseLUKSValue("data", "dev=/dev/vdb,mount=/data")
	if err != nil {
		t.Fatal(err)
	}
	// name is passthrough to volume name and default secretName
	if lv.Name != "data" || lv.SecretName != "data" {
		t.Errorf("name/secretName = %q/%q, want data/data", lv.Name, lv.SecretName)
	}
	if lv.Dev != "/dev/vdb" || lv.Mount != "/data" {
		t.Errorf("dev/mount = %q/%q", lv.Dev, lv.Mount)
	}
	// defaults
	if lv.FSType != "ext4" || lv.Mode != "open" {
		t.Errorf("fstype/mode defaults = %q/%q, want ext4/open", lv.FSType, lv.Mode)
	}
}

func TestParseLUKSValueOverrides(t *testing.T) {
	lv, err := parseLUKSValue("scratch",
		"dev=/dev/vdc,mount=/scratch,fstype=xfs,mode=format-if-empty")
	if err != nil {
		t.Fatal(err)
	}
	if lv.FSType != "xfs" || lv.Mode != "format-if-empty" {
		t.Errorf("overrides not applied: fstype=%q mode=%q", lv.FSType, lv.Mode)
	}
}

func TestParseLUKSValueErrors(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{"missing dev", "mount=/data", "one of dev= or pvc= is required"},
		{"dev and pvc together", "dev=/dev/vdb,pvc=my-claim,mount=/data", "mutually exclusive"},
		{"bad pvc name", "pvc=Not_A_Claim,mount=/data", "pvc= must be a valid claim name"},
		{"missing mount", "dev=/dev/vdb", "mount= must be an absolute path"},
		{"relative mount", "dev=/dev/vdb,mount=data", "mount= must be an absolute path"},
		{"dropped secret knob", "dev=/dev/vdb,mount=/data,secret=secret/data/x#p", `unknown key "secret"`},
		{"unknown key", "dev=/dev/vdb,mount=/data,zzz=abc", `unknown key "zzz"`},
		{"unknown mode", "dev=/dev/vdb,mount=/data,mode=maybe", "unknown mode"},
		{"not kv pair", "dev=/dev/vdb,justaword,mount=/data", "is not a key=value pair"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseLUKSValue("data", tc.value)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestParseLUKSValueInvalidName(t *testing.T) {
	if _, err := parseLUKSValue("Bad_Name", "dev=/dev/vdb,mount=/data"); err == nil {
		t.Error("expected DNS-1123 name error")
	}
}

func TestParseLUKSVolumesNilWhenAbsent(t *testing.T) {
	vols, err := parseLUKSVolumes(map[string]string{"unrelated": "true"}, nil)
	if err != nil || vols != nil {
		t.Errorf("no luks-* → (nil,nil), got (%v, %v)", vols, err)
	}
}

func TestParseLUKSVolumesRequiresSecretsInject(t *testing.T) {
	_, err := parseLUKSVolumes(map[string]string{
		luksAnnotationPrefix + "data": "dev=/dev/vdb,mount=/data",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), AnnotationSecretsInject) {
		t.Errorf("want error mentioning secrets-inject, got %v", err)
	}
}

func TestParseLUKSVolumesRequiresMatchingSecretsEntry(t *testing.T) {
	secrets := &secretsInjection{Entries: []secretEntry{{Name: "other", Path: "secret/data/x"}}}
	_, err := parseLUKSVolumes(map[string]string{
		luksAnnotationPrefix + "data": "dev=/dev/vdb,mount=/data",
	}, secrets)
	if err == nil || !strings.Contains(err.Error(), "not declared by a matching") {
		t.Errorf("want error about missing matching secret entry, got %v", err)
	}
}

func TestParseLUKSVolumesSortsByName(t *testing.T) {
	secrets := &secretsInjection{Entries: []secretEntry{
		{Name: "alpha", Path: "secret/data/x"}, {Name: "zulu", Path: "secret/data/y"},
	}}
	vols, err := parseLUKSVolumes(map[string]string{
		luksAnnotationPrefix + "zulu":  "dev=/dev/vdc,mount=/z",
		luksAnnotationPrefix + "alpha": "dev=/dev/vdb,mount=/a",
	}, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if len(vols) != 2 || vols[0].Name != "alpha" || vols[1].Name != "zulu" {
		t.Errorf("volumes not sorted: %+v", vols)
	}
}

func luksTestConfig() Config {
	c := secretsTestConfig()
	c.LUKSOpenImage = "ghcr.io/confidential-dot-ai/luks-open:test"
	c.LUKSDeviceAllowlist = []string{"/dev/vdb", "/dev/vdc"}
	return c
}

func TestValidateLUKSDevice(t *testing.T) {
	allow := []string{"/dev/vdb", "/dev/disk/by-id/virtio-luks-*"}
	cases := []struct {
		name, dev string
		allowlist []string
		wantErr   string // empty = allowed
	}{
		{"allowed exact", "/dev/vdb", allow, ""},
		{"allowed glob", "/dev/disk/by-id/virtio-luks-data", allow, ""},
		{"empty allowlist fails closed", "/dev/vdb", nil, "no --luks-device-allowlist"},
		{"no match", "/dev/vdc", allow, "matches no"},
		{"relative", "dev/vdb", allow, "under /dev"},
		{"outside /dev", "/tmp/vdb", allow, "under /dev"},
		{"dot-dot escape", "/dev/../etc/passwd", allow, "under /dev"},
		{"trailing slash", "/dev/vdb/", allow, "under /dev"},
		{"bare /dev", "/dev", allow, "under /dev"},
		{"bad pattern fails closed", "/dev/vdb", []string{"[unclosed"}, "pattern"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateLUKSDevice(tc.dev, tc.allowlist)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("want allowed, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

// A dev= LUKS pod is denied at admission unless the device matches the
// operator's --luks-device-allowlist; pvc= volumes need no allowlist.
func TestHandleEnforcesLUKSDeviceAllowlist(t *testing.T) {
	devPod := func() *corev1.Pod {
		pod := luksHandlePod()
		pod.Annotations[luksAnnotationPrefix+"data"] = "dev=/dev/vdb,mount=/data"
		return pod
	}

	t.Run("denied with empty allowlist", func(t *testing.T) {
		cfg := luksTestConfig()
		cfg.LUKSDeviceAllowlist = nil
		resp := handleAdmission(t, cfg, devPod())
		if resp.Allowed {
			t.Fatal("dev= admitted with no --luks-device-allowlist configured")
		}
		if resp.Result == nil || !strings.Contains(resp.Result.Message, "luks-device-allowlist") {
			t.Fatalf("denial message = %+v, want it to mention the allowlist", resp.Result)
		}
	})
	t.Run("denied when no pattern matches", func(t *testing.T) {
		cfg := luksTestConfig()
		cfg.LUKSDeviceAllowlist = []string{"/dev/disk/by-id/virtio-luks-*"}
		if resp := handleAdmission(t, cfg, devPod()); resp.Allowed {
			t.Fatal("dev= admitted for a device outside the allowlist")
		}
	})
	t.Run("allowed when a pattern matches", func(t *testing.T) {
		if resp := handleAdmission(t, luksTestConfig(), devPod()); !resp.Allowed {
			t.Fatalf("dev= denied despite matching the allowlist: %+v", resp.Result)
		}
	})
	t.Run("pvc= needs no allowlist", func(t *testing.T) {
		cfg := luksTestConfig()
		cfg.LUKSDeviceAllowlist = nil
		if resp := handleAdmission(t, cfg, luksHandlePod()); !resp.Allowed {
			t.Fatalf("pvc= denied by the device allowlist: %+v", resp.Result)
		}
	})
}

func TestMutatePodInjectsLUKSContainer(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	inj := &injection{
		WorkloadID: "api",
		Secrets: &secretsInjection{
			Entries: []secretEntry{{Name: "data", Path: "secret/data/api/luks", Field: "passphrase"}},
		},
		LUKS: []luksVolume{{
			Name: "data", Dev: "/dev/vdb", Mount: "/data",
			SecretName: "data",
			FSType: "ext4", Mode: "open",
		}},
	}
	mutatePod(pod, inj, luksTestConfig())

	// c8s-luks-open init container present, positioned after c8s-secrets-agent-init
	openIdx, agentInitIdx := -1, -1
	for i, c := range pod.Spec.InitContainers {
		switch c.Name {
		case "c8s-luks-open":
			openIdx = i
		case "c8s-secrets-agent-init":
			agentInitIdx = i
		}
	}
	if openIdx < 0 {
		t.Fatal("c8s-luks-open init container not injected")
	}
	if agentInitIdx < 0 || openIdx < agentInitIdx {
		t.Errorf("c8s-luks-open at %d must come after c8s-secrets-agent-init at %d", openIdx, agentInitIdx)
	}
	openC := pod.Spec.InitContainers[openIdx]
	if openC.SecurityContext == nil || openC.SecurityContext.Privileged == nil || !*openC.SecurityContext.Privileged {
		t.Errorf("c8s-luks-open must be privileged (found %+v)", openC.SecurityContext)
	}
	// --volume=data=/dev/vdb:data:ext4:open should be in args
	joined := strings.Join(openC.Args, " ")
	if !strings.Contains(joined, "--volume=data=/dev/vdb:data:ext4:open") {
		t.Errorf("volume spec missing from args: %v", openC.Args)
	}
	// Downward-API pod UID for the per-pod mapper names.
	uidEnv := false
	for _, e := range openC.Env {
		if e.Name == "C8S_POD_UID" && e.ValueFrom != nil && e.ValueFrom.FieldRef != nil &&
			e.ValueFrom.FieldRef.FieldPath == "metadata.uid" {
			uidEnv = true
		}
	}
	if !uidEnv {
		t.Errorf("c8s-luks-open missing the downward-API C8S_POD_UID env: %+v", openC.Env)
	}
	// App container gets a volume mount at /data
	found := false
	for _, vm := range pod.Spec.Containers[0].VolumeMounts {
		if vm.MountPath == "/data" && vm.Name == luksDataVolume {
			found = true
		}
	}
	if !found {
		t.Errorf("app container missing volume mount at /data (%+v)", pod.Spec.Containers[0].VolumeMounts)
	}
	// host-dev volume declared
	hostDev := false
	for _, v := range pod.Spec.Volumes {
		if v.Name == "host-dev" && v.HostPath != nil && v.HostPath.Path == "/dev" {
			hostDev = true
		}
	}
	if !hostDev {
		t.Error("host-dev hostPath volume not declared on pod")
	}
}

// TestMutatePodInjectsPVCLUKSVolume pins the pvc= contract: the webhook
// declares the claim at pod scope, maps it as a raw volumeDevice on the
// luks-open init container at the fixed /c8s-dev/<name> path, and passes that
// path — not a host device — in the --volume spec. The operator pastes only
// annotations; no PodSpec surgery.
func TestMutatePodInjectsPVCLUKSVolume(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	inj := &injection{
		WorkloadID: "api",
		Secrets: &secretsInjection{
			Entries: []secretEntry{{Name: "data", Path: "secret/data/api/luks-data", Field: "passphrase"}},
		},
		LUKS: []luksVolume{{
			Name: "data", PVC: "c8s-luks-api-data", Mount: "/data",
			SecretName: "data",
			FSType: "ext4", Mode: "format-if-empty",
		}},
	}
	mutatePod(pod, inj, luksTestConfig())

	var openC *corev1.Container
	for i, c := range pod.Spec.InitContainers {
		if c.Name == "c8s-luks-open" {
			openC = &pod.Spec.InitContainers[i]
		}
	}
	if openC == nil {
		t.Fatal("c8s-luks-open init container not injected")
	}
	joined := strings.Join(openC.Args, " ")
	if !strings.Contains(joined, "--volume=data=/c8s-dev/data:data:ext4:format-if-empty") {
		t.Errorf("volume spec must use the in-container device path: %v", openC.Args)
	}
	devFound := false
	for _, d := range openC.VolumeDevices {
		if d.Name == "c8s-luks-pvc-data" && d.DevicePath == "/c8s-dev/data" {
			devFound = true
		}
	}
	if !devFound {
		t.Errorf("luks-open missing the claim volumeDevice (%+v)", openC.VolumeDevices)
	}
	pvcVol := false
	for _, v := range pod.Spec.Volumes {
		if v.Name == "c8s-luks-pvc-data" && v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName == "c8s-luks-api-data" {
			pvcVol = true
		}
	}
	if !pvcVol {
		t.Errorf("pod missing the PVC volume declaration (%+v)", pod.Spec.Volumes)
	}
	// The app container must NOT see the raw device — only the decrypted fs.
	if len(pod.Spec.Containers[0].VolumeDevices) != 0 {
		t.Errorf("app container must not get raw volumeDevices (%+v)", pod.Spec.Containers[0].VolumeDevices)
	}
	// CRITICAL: a pvc= pod must NOT mount host /dev — bind-mounting it clobbers
	// the CRI-mapped volumeDevice so cryptsetup sees "device does not exist".
	for _, vm := range openC.VolumeMounts {
		if vm.MountPath == "/dev" {
			t.Errorf("pvc= luks-open must not mount host /dev (clobbers the volumeDevice): %+v", openC.VolumeMounts)
		}
	}
	for _, v := range pod.Spec.Volumes {
		if v.Name == "host-dev" {
			t.Errorf("pvc= pod must not declare the host-dev volume: %+v", pod.Spec.Volumes)
		}
	}
}

// A pod may not mix dev= (local) and pvc= LUKS volumes: they need incompatible
// /dev setups in the single luks-open container.
func TestParseLUKSRejectsMixedDevAndPVC(t *testing.T) {
	secrets := &secretsInjection{Entries: []secretEntry{
		{Name: "local", Path: "secret/data/api/l", Field: "passphrase"},
		{Name: "claim", Path: "secret/data/api/c", Field: "passphrase"},
	}}
	anns := map[string]string{
		luksAnnotationPrefix + "local": "dev=/dev/vdb,mount=/a",
		luksAnnotationPrefix + "claim": "pvc=c8s-luks-api-c,mount=/b",
	}
	_, err := parseLUKSVolumes(anns, secrets)
	if err == nil || !strings.Contains(err.Error(), "may not mix dev= (local) and pvc=") {
		t.Fatalf("expected mixed dev=/pvc= rejection, got %v", err)
	}
}

// TestMutatePodInjectsMultipleLUKSVolumes proves every LUKS volume lands in the
// app container (the shared c8s-luks-data volume is mounted once per subPath,
// not deduped by volume name) and that a webhook reinvocation converges.
func TestMutatePodInjectsMultipleLUKSVolumes(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	inj := &injection{
		WorkloadID: "api",
		Secrets: &secretsInjection{Entries: []secretEntry{
			{Name: "alpha", Path: "secret/data/api/a", Field: "p"},
			{Name: "zulu", Path: "secret/data/api/z", Field: "p"},
		}},
		LUKS: []luksVolume{
			{Name: "alpha", Dev: "/dev/vdb", Mount: "/a", SecretName: "alpha", FSType: "ext4", Mode: "open"},
			{Name: "zulu", Dev: "/dev/vdc", Mount: "/z", SecretName: "zulu", FSType: "ext4", Mode: "open"},
		},
	}
	mutatePod(pod, inj, luksTestConfig())
	mutatePod(pod, inj, luksTestConfig())

	app := pod.Spec.Containers[0]
	for _, want := range []struct{ path, subPath string }{{"/a", "alpha"}, {"/z", "zulu"}} {
		n := 0
		for _, vm := range app.VolumeMounts {
			if vm.Name == luksDataVolume && vm.MountPath == want.path && vm.SubPath == want.subPath {
				n++
			}
		}
		if n != 1 {
			t.Errorf("app mounts of %s at %s = %d, want 1 (%+v)", luksDataVolume, want.path, n, app.VolumeMounts)
		}
	}
	open := 0
	for _, c := range pod.Spec.InitContainers {
		if c.Name == "c8s-luks-open" {
			open++
		}
	}
	if open != 1 {
		t.Errorf("c8s-luks-open containers after two injections = %d, want 1", open)
	}
}

// Under --kata-enforce, a LUKS pod must end up under kata: the injected
// luks-open container is privileged, tolerable only inside a VM boundary.
func TestHandleRequiresKataForLUKS(t *testing.T) {
	kataCfg := func() Config {
		cfg := luksTestConfig()
		cfg.KataEnforce = true
		return cfg
	}

	t.Run("denied with a non-kata runtimeClassName", func(t *testing.T) {
		pod := luksHandlePod()
		rc := "gvisor"
		pod.Spec.RuntimeClassName = &rc
		resp := handleAdmission(t, kataCfg(), pod)
		if resp.Allowed {
			t.Fatal("LUKS pod admitted under a non-kata runtime class with kata enforcement on")
		}
		if resp.Result == nil || !strings.Contains(resp.Result.Message, "kata") {
			t.Fatalf("denial message = %+v, want it to mention kata", resp.Result)
		}
	})
	t.Run("denied with a host namespace", func(t *testing.T) {
		pod := luksHandlePod()
		pod.Spec.HostPID = true // kata cannot honor host namespaces, so no class is injected
		if resp := handleAdmission(t, kataCfg(), pod); resp.Allowed {
			t.Fatal("LUKS pod with hostPID admitted despite being kata-incompatible")
		}
	})
	t.Run("allowed when the webhook injects the kata class", func(t *testing.T) {
		if resp := handleAdmission(t, kataCfg(), luksHandlePod()); !resp.Allowed {
			t.Fatalf("LUKS pod denied despite kata injection: %+v", resp.Result)
		}
	})
	t.Run("allowed with a pod-set kata class", func(t *testing.T) {
		pod := luksHandlePod()
		rc := kataSnpRuntimeClass
		pod.Spec.RuntimeClassName = &rc
		if resp := handleAdmission(t, kataCfg(), pod); !resp.Allowed {
			t.Fatalf("LUKS pod denied despite an explicit kata class: %+v", resp.Result)
		}
	})
	t.Run("no check when enforcement is off", func(t *testing.T) {
		pod := luksHandlePod()
		rc := "gvisor"
		pod.Spec.RuntimeClassName = &rc
		if resp := handleAdmission(t, luksTestConfig(), pod); !resp.Allowed {
			t.Fatalf("kata check must be inert without --kata-enforce (baremetal is the chart's guard): %+v", resp.Result)
		}
	})
}
