package luks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/api/resource"
)

// stubKubectl replaces kubectlRun for the test, recording every invocation.
// respond maps the first arg (verb) to canned output.
func stubKubectl(t *testing.T, respond map[string]string) *[][]string {
	t.Helper()
	var calls [][]string
	orig := kubectlRun
	kubectlRun = func(_ context.Context, stdin string, args ...string) (string, error) {
		calls = append(calls, append([]string{stdin}, args...))
		return respond[args[0]], nil
	}
	t.Cleanup(func() { kubectlRun = orig })
	return &calls
}

func pvcCreateConfig() createConfig {
	return createConfig{
		workload: "api", name: "data", driver: "pvc",
		fstype: "ext4", mount: "/data", namespace: "default",
		size: resource.MustParse("1Gi"),
	}
}

func TestProvisionPVCManifest(t *testing.T) {
	calls := stubKubectl(t, map[string]string{"get": "", "apply": "persistentvolumeclaim/c8s-luks-api-data created"})

	claim, notes, err := provisionPVC(context.Background(), pvcCreateConfig())
	if err != nil {
		t.Fatalf("provisionPVC: %v", err)
	}
	if claim != "c8s-luks-api-data" {
		t.Errorf("claim = %q, want c8s-luks-api-data", claim)
	}
	if len(notes) == 0 {
		t.Error("expected operator notes for the pvc driver")
	}

	if len(*calls) != 2 || (*calls)[1][1] != "apply" {
		t.Fatalf("expected get-then-apply, got %v", *calls)
	}
	var m struct {
		Kind     string `yaml:"kind"`
		Metadata struct {
			Name      string `yaml:"name"`
			Namespace string `yaml:"namespace"`
		} `yaml:"metadata"`
		Spec struct {
			AccessModes      []string `yaml:"accessModes"`
			VolumeMode       string   `yaml:"volumeMode"`
			StorageClassName string   `yaml:"storageClassName"`
			Resources        struct {
				Requests map[string]string `yaml:"requests"`
			} `yaml:"resources"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal([]byte((*calls)[1][0]), &m); err != nil {
		t.Fatalf("applied manifest does not parse: %v", err)
	}
	// INVARIANT: raw block, not filesystem — the pod luksFormats the device
	// itself; a Filesystem-mode claim would hand the pod an fs it can't open.
	if m.Spec.VolumeMode != "Block" {
		t.Errorf("volumeMode = %q, want Block", m.Spec.VolumeMode)
	}
	if m.Kind != "PersistentVolumeClaim" || m.Metadata.Name != "c8s-luks-api-data" || m.Metadata.Namespace != "default" {
		t.Errorf("unexpected manifest identity: %+v", m)
	}
	if got := m.Spec.Resources.Requests["storage"]; got != "1Gi" {
		t.Errorf("storage request = %q, want 1Gi", got)
	}
	if m.Spec.StorageClassName != "" {
		t.Errorf("storageClassName should be omitted by default, got %q", m.Spec.StorageClassName)
	}
}

func TestProvisionPVCStorageClassAndExists(t *testing.T) {
	t.Run("storage class set", func(t *testing.T) {
		calls := stubKubectl(t, map[string]string{"get": "", "apply": "ok"})
		cfg := pvcCreateConfig()
		cfg.storageClass = "fast-block"
		if _, _, err := provisionPVC(context.Background(), cfg); err != nil {
			t.Fatalf("provisionPVC: %v", err)
		}
		if !strings.Contains((*calls)[1][0], "storageClassName: fast-block") {
			t.Errorf("manifest missing storageClassName:\n%s", (*calls)[1][0])
		}
	})
	t.Run("claim already exists", func(t *testing.T) {
		stubKubectl(t, map[string]string{"get": "persistentvolumeclaim/c8s-luks-api-data"})
		_, _, err := provisionPVC(context.Background(), pvcCreateConfig())
		if err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("err = %v, want already-exists refusal", err)
		}
	})
}

// The pvc driver must always emit mode=format-if-empty — nothing can
// luksFormat an unbound claim, so first-boot formatting in the pod is the only
// coherent mode, regardless of --defer-format.
func TestProvisionRoutesPVCFormatIfEmpty(t *testing.T) {
	stubKubectl(t, map[string]string{"get": "", "apply": "ok"})
	prov, err := provision(context.Background(), pvcCreateConfig(), []byte("unused"))
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if prov.mode != "format-if-empty" {
		t.Errorf("mode = %q, want format-if-empty", prov.mode)
	}
	if prov.devToken != "pvc=c8s-luks-api-data" {
		t.Errorf("devToken = %q, want pvc=c8s-luks-api-data", prov.devToken)
	}
	if prov.volume != nil || prov.mount != nil {
		t.Errorf("pvc driver must emit no PodSpec extras (webhook attaches the claim), got volume=%v mount=%v", prov.volume, prov.mount)
	}
}

func podsJSON(entries ...map[string]any) string {
	b, _ := json.Marshal(map[string]any{"items": entries})
	return string(b)
}

func podWithClaim(name, claim string) map[string]any {
	return map[string]any{
		"metadata": map[string]any{"name": name},
		"spec": map[string]any{
			"volumes": []map[string]any{
				{"persistentVolumeClaim": map[string]any{"claimName": claim}},
			},
		},
	}
}

func TestPVCConsumers(t *testing.T) {
	stubKubectl(t, map[string]string{"get": podsJSON(
		podWithClaim("user-pod", "c8s-luks-api-data"),
		podWithClaim("other-pod", "unrelated-claim"),
	)})
	users, err := pvcConsumers(context.Background(), "c8s-luks-api-data", "default")
	if err != nil {
		t.Fatalf("pvcConsumers: %v", err)
	}
	if len(users) != 1 || users[0] != "user-pod" {
		t.Errorf("users = %v, want [user-pod]", users)
	}
}

// A refused destroy must leave the KV entry intact: the passphrase is the only
// way to ever open the volume again.
func TestRunDestroyPVCInUse(t *testing.T) {
	kvDeleted := false
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secret/metadata/api/luks-data", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			kvDeleted = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := newBao(srv.URL, "root")

	cfg := destroyCfg{workload: "api", name: "data", driver: "pvc", namespace: "default"}

	t.Run("refuses while mounted, KV intact", func(t *testing.T) {
		stubKubectl(t, map[string]string{"get": podsJSON(podWithClaim("user-pod", "c8s-luks-api-data"))})
		err := runDestroy(context.Background(), c, cfg)
		if err == nil || !strings.Contains(err.Error(), "mounted by pod(s) user-pod") {
			t.Fatalf("err = %v, want in-use refusal", err)
		}
		if kvDeleted {
			t.Fatal("KV entry deleted despite the refusal")
		}
	})

	t.Run("force deletes claim and KV", func(t *testing.T) {
		calls := stubKubectl(t, map[string]string{"get": podsJSON(podWithClaim("user-pod", "c8s-luks-api-data"))})
		fcfg := cfg
		fcfg.force = true
		if err := runDestroy(context.Background(), c, fcfg); err != nil {
			t.Fatalf("runDestroy --force: %v", err)
		}
		if !kvDeleted {
			t.Fatal("KV entry not deleted")
		}
		deleted := false
		for _, call := range *calls {
			if call[1] == "delete" && call[2] == "pvc" && call[3] == "c8s-luks-api-data" {
				deleted = true
			}
		}
		if !deleted {
			t.Fatalf("kubectl delete pvc not invoked: %v", *calls)
		}
	})
}
