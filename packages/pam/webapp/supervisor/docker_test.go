package supervisor

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestDockerLaunchDestroy launches a real runner (needs infisical-webapp-runner:dev) on alternate gateway ports and
// checks destroy leaves nothing behind. Run with IWA_DOCKER_TESTS=1 go test -run Docker.
func TestDockerLaunchDestroy(t *testing.T) {
	if os.Getenv("IWA_DOCKER_TESTS") != "1" {
		t.Skip("set IWA_DOCKER_TESTS=1 to run docker-backed tests")
	}
	out, err := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", "infisical-webapp-runner:dev").Output()
	if err != nil {
		t.Skip("image infisical-webapp-runner:dev not present")
	}
	imageID := strings.TrimSpace(string(out))
	ref := "infisical-webapp-runner@" + imageID

	var logs bytes.Buffer
	s := newServer(Config{StateDir: t.TempDir(), Images: []string{ref}, MaxRunners: 50,
		Logger: log.New(&logs, "", 0)}, newExecDocker(log.New(&logs, "", 0)))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := s.Prepare(ctx); err != nil {
		t.Fatal(err)
	}

	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	id := fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	req := validRequest(t, id)
	req["image"] = ref
	req["gatewayAgentAddr"] = "172.28.0.1:17799"
	req["egressProxyAddr"] = "172.28.0.1:13199"

	code, res := do(t, s, "POST", "/v1/runners", req)
	t.Cleanup(func() { _ = s.removeSession(context.Background(), id) })
	if code != http.StatusCreated {
		t.Fatalf("launch: %d %v\n%s", code, res, logs.String())
	}
	short := shortID(id)
	img, err := exec.Command("docker", "inspect", "--format", "{{.Image}}", runnerName(short)).Output()
	if err != nil || strings.TrimSpace(string(img)) != imageID {
		t.Fatalf("runner image %q, want %s (%v)", img, imageID, err)
	}
	if code, res := do(t, s, "GET", "/v1/runners/"+id, nil); code != http.StatusOK {
		t.Fatalf("status: %d %v", code, res)
	}
	for i := 0; i < 2; i++ {
		if code, res := do(t, s, "DELETE", "/v1/runners/"+id, nil); code != http.StatusOK {
			t.Fatalf("destroy %d: %d %v", i, code, res)
		}
	}
	left, err := exec.Command("docker", "ps", "-aq", "--filter", "label="+SessionLabel+"="+id).Output()
	if err != nil || strings.TrimSpace(string(left)) != "" {
		t.Fatalf("leftover containers %q (%v)", left, err)
	}
	if strings.Contains(logs.String(), req["runnerToken"].(string)) {
		t.Fatal("supervisor logs leak the runner token")
	}
}
