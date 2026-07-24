package luksopen

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseVolumeSpecs(t *testing.T) {
	vols, err := ParseVolumeSpecs([]string{
		"data=/dev/vdb:data:ext4:open",
		"scratch=/dev/vdc:scratch-secret:xfs:format-if-empty",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(vols) != 2 {
		t.Fatalf("want 2 vols, got %d", len(vols))
	}
	if vols[0].Name != "data" || vols[0].Dev != "/dev/vdb" || vols[0].SecretName != "data" ||
		vols[0].FSType != "ext4" || vols[0].Mode != "open" {
		t.Errorf("vols[0] wrong: %+v", vols[0])
	}
	if vols[1].SecretName != "scratch-secret" || vols[1].Mode != "format-if-empty" {
		t.Errorf("vols[1] wrong: %+v", vols[1])
	}
}

func TestParseVolumeSpecsErrors(t *testing.T) {
	cases := []struct {
		spec, want string
	}{
		{"no-equals", "want <name>=<dev>"},
		{"data=", "want <name>=<dev>"},
		{"data=/dev/vdb", "want 4 colon-separated fields"},
		{"data=/dev/vdb:sec:ext4:wat", "mode must be open or format-if-empty"},
		{"data=:sec:ext4:open", "dev/secretName/fstype must be non-empty"},
		{"data=/dev/vdb:sec:btrfs:open", "unsupported fstype"},
		{"data=/dev/vdb:sec:vfat:open", "unsupported fstype"},
	}
	for _, tc := range cases {
		t.Run(tc.spec, func(t *testing.T) {
			_, err := ParseVolumeSpecs([]string{tc.spec})
			if err == nil {
				t.Fatalf("expected error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestTrimTrailingNewline(t *testing.T) {
	if got := string(trimTrailingNewline([]byte("hello\n"))); got != "hello" {
		t.Errorf("got %q", got)
	}
	if got := string(trimTrailingNewline([]byte("hello\r\n"))); got != "hello" {
		t.Errorf("got %q", got)
	}
	if got := string(trimTrailingNewline([]byte("hello"))); got != "hello" {
		t.Errorf("got %q", got)
	}
}

func TestParseStatusDevice(t *testing.T) {
	out := "/dev/mapper/c8s-x is active.\n  type:    LUKS2\n  device:  /dev/vdb\n  sector size:  512\n"
	dev, err := parseStatusDevice(out)
	if err != nil || dev != "/dev/vdb" {
		t.Fatalf("parseStatusDevice = (%q, %v), want /dev/vdb", dev, err)
	}
	if _, err := parseStatusDevice("no such line\n"); err == nil {
		t.Fatal("missing device: line must be an error")
	}
	if _, err := parseStatusDevice("  device:   \n"); err == nil {
		t.Fatal("empty device: line must be an error")
	}
}

// seamRecorder stubs every exec/syscall seam and records calls. The zero-value
// behavior is a fresh LUKS device with no existing mapper: isLuks true, mapper
// absent, no mkfs needed.
type seamRecorder struct {
	calls []string // "cryptsetup luksOpen ...", "mkfs ext4 /dev/...", "mount ..."

	isLUKS       bool
	blank        bool
	mapperExists bool
	statusOut    string
	rdevs        map[string]uint64
	needsMkfs    bool
}

func installSeams(t *testing.T, r *seamRecorder) {
	t.Helper()
	saveCryptsetup, saveCheck, saveStatus := runCryptsetup, runCryptsetupCheck, runCryptsetupStatus
	saveBlank, saveNeedsMkfs, saveMkfs, saveMount := devBlank, mapperNeedsMkfs, mkfs, mount
	saveStatMapper, saveStatRdev := statMapper, statRdev
	t.Cleanup(func() {
		runCryptsetup, runCryptsetupCheck, runCryptsetupStatus = saveCryptsetup, saveCheck, saveStatus
		devBlank, mapperNeedsMkfs, mkfs, mount = saveBlank, saveNeedsMkfs, saveMkfs, saveMount
		statMapper, statRdev = saveStatMapper, saveStatRdev
	})

	runCryptsetup = func(passphrase []byte, args ...string) error {
		r.calls = append(r.calls, "cryptsetup "+strings.Join(args, " "))
		return nil
	}
	runCryptsetupCheck = func(sub, dev string) (bool, error) {
		r.calls = append(r.calls, "check "+sub+" "+dev)
		return r.isLUKS, nil
	}
	runCryptsetupStatus = func(mapperName string) (string, error) {
		r.calls = append(r.calls, "status "+mapperName)
		return r.statusOut, nil
	}
	devBlank = func(dev string) (bool, error) {
		r.calls = append(r.calls, "blank "+dev)
		return r.blank, nil
	}
	mapperNeedsMkfs = func(mapperPath string) (bool, error) {
		return r.needsMkfs, nil
	}
	mkfs = func(fstype, dev string) error {
		r.calls = append(r.calls, "mkfs "+fstype+" "+dev)
		return nil
	}
	mount = func(fstype, src, dst string) error {
		r.calls = append(r.calls, "mount "+fstype+" "+src+" "+dst)
		return nil
	}
	statMapper = func(path string) (os.FileInfo, error) {
		if r.mapperExists {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}
	statRdev = func(path string) (uint64, error) {
		rdev, ok := r.rdevs[path]
		if !ok {
			return 0, fmt.Errorf("stat %s: no such device", path)
		}
		return rdev, nil
	}
}

func (r *seamRecorder) called(prefix string) bool {
	for _, c := range r.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

const testPodUID = "8d7f5f8e-0000-4111-8222-333344445555"

// testConfig writes a passphrase file and returns a Config pointing at it.
func testConfig(t *testing.T) Config {
	t.Helper()
	secrets := t.TempDir()
	if err := os.WriteFile(filepath.Join(secrets, "data"), []byte("passphrase\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return Config{SecretsDir: secrets, MountRoot: t.TempDir()}
}

func testVolume(mode string) Volume {
	return Volume{Name: "data", Dev: "/dev/vdb", SecretName: "data", FSType: "ext4", Mode: mode}
}

func TestOpenOneRefusesNonLUKSInOpenMode(t *testing.T) {
	r := &seamRecorder{isLUKS: false}
	installSeams(t, r)
	err := openOne(testConfig(t), testPodUID, testVolume("open"))
	if err == nil || !strings.Contains(err.Error(), "not LUKS-formatted") {
		t.Fatalf("err = %v, want not-LUKS refusal", err)
	}
	if r.called("cryptsetup luksFormat") {
		t.Fatalf("luksFormat must not run in mode=open: %v", r.calls)
	}
}

func TestOpenOneRefusesFormatOnNonBlankDevice(t *testing.T) {
	r := &seamRecorder{isLUKS: false, blank: false}
	installSeams(t, r)
	err := openOne(testConfig(t), testPodUID, testVolume("format-if-empty"))
	if err == nil || !strings.Contains(err.Error(), "refusing to luksFormat") {
		t.Fatalf("err = %v, want refusal on non-blank device", err)
	}
	if r.called("cryptsetup luksFormat") {
		t.Fatalf("luksFormat must not run on a device with an existing signature: %v", r.calls)
	}
}

func TestOpenOneFormatsBlankDevice(t *testing.T) {
	r := &seamRecorder{isLUKS: false, blank: true}
	installSeams(t, r)
	if err := openOne(testConfig(t), testPodUID, testVolume("format-if-empty")); err != nil {
		t.Fatal(err)
	}
	if !r.called("blank /dev/vdb") {
		t.Fatalf("blkid probe must run before luksFormat: %v", r.calls)
	}
	if !r.called("cryptsetup luksFormat --batch-mode /dev/vdb") {
		t.Fatalf("luksFormat missing: %v", r.calls)
	}
}

func TestOpenOneMapperNameIncludesPodUID(t *testing.T) {
	r := &seamRecorder{isLUKS: true}
	installSeams(t, r)
	if err := openOne(testConfig(t), testPodUID, testVolume("open")); err != nil {
		t.Fatal(err)
	}
	wantMapper := "c8s-" + testPodUID + "-data"
	if !r.called("cryptsetup luksOpen /dev/vdb " + wantMapper) {
		t.Fatalf("luksOpen must use the per-pod mapper name %s: %v", wantMapper, r.calls)
	}
	if !r.called("mount ext4 /dev/mapper/" + wantMapper) {
		t.Fatalf("mount must use the per-pod mapper path: %v", r.calls)
	}
}

func TestOpenOneAdoptionRejectsDeviceMismatch(t *testing.T) {
	mapper := "c8s-" + testPodUID + "-data"
	r := &seamRecorder{
		isLUKS:       true,
		mapperExists: true,
		statusOut:    "  type: LUKS2\n  device: /dev/vdz\n",
		rdevs:        map[string]uint64{"/dev/vdz": 100, "/dev/vdb": 200},
		needsMkfs:    true, // even a mapper that "needs" mkfs must not get one
	}
	installSeams(t, r)
	err := openOne(testConfig(t), testPodUID, testVolume("format-if-empty"))
	if err == nil || !strings.Contains(err.Error(), "refusing to adopt") {
		t.Fatalf("err = %v, want adoption refusal on device mismatch", err)
	}
	if !r.called("status " + mapper) {
		t.Fatalf("adoption must verify via cryptsetup status: %v", r.calls)
	}
	if r.called("mkfs") || r.called("mount") || r.called("cryptsetup luksOpen") {
		t.Fatalf("nothing may run after a failed adoption check: %v", r.calls)
	}
}

func TestOpenOneAdoptionVerifiesBeforeMkfs(t *testing.T) {
	r := &seamRecorder{
		isLUKS:       true,
		mapperExists: true,
		statusOut:    "  device: /dev/vdb\n",
		rdevs:        map[string]uint64{"/dev/vdb": 200},
		needsMkfs:    true,
	}
	installSeams(t, r)
	if err := openOne(testConfig(t), testPodUID, testVolume("format-if-empty")); err != nil {
		t.Fatal(err)
	}
	statusIdx, mkfsIdx := -1, -1
	for i, c := range r.calls {
		if strings.HasPrefix(c, "status ") && statusIdx < 0 {
			statusIdx = i
		}
		if strings.HasPrefix(c, "mkfs ") && mkfsIdx < 0 {
			mkfsIdx = i
		}
	}
	if statusIdx < 0 || mkfsIdx < 0 || mkfsIdx < statusIdx {
		t.Fatalf("mkfs (idx %d) must come after the adoption check (idx %d): %v", mkfsIdx, statusIdx, r.calls)
	}
}

func TestRunRequiresPodUID(t *testing.T) {
	r := &seamRecorder{isLUKS: true}
	installSeams(t, r)
	t.Setenv(podUIDEnv, "")
	cfg := testConfig(t)
	cfg.VolumeSpecs = []string{"data=/dev/vdb:data:ext4:open"}
	err := Run(cfg)
	if err == nil || !strings.Contains(err.Error(), podUIDEnv) {
		t.Fatalf("err = %v, want missing %s error", err, podUIDEnv)
	}
	if len(r.calls) != 0 {
		t.Fatalf("nothing may run without a pod UID: %v", r.calls)
	}
}

func TestVerifyAdoptedMapperFailsClosed(t *testing.T) {
	r := &seamRecorder{statusOut: "garbage with no device line\n"}
	installSeams(t, r)
	if err := verifyAdoptedMapper("c8s-x-data", "/dev/vdb"); err == nil {
		t.Fatal("unparseable cryptsetup status must fail adoption")
	}

	r.statusOut = "  device: /dev/vdz\n"
	r.rdevs = map[string]uint64{"/dev/vdb": 200} // backing device missing
	if err := verifyAdoptedMapper("c8s-x-data", "/dev/vdb"); err == nil {
		t.Fatal("unstat-able backing device must fail adoption")
	}
}
