package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
)

type measureSample struct {
	AtMs     int64   `json:"atMs"`
	CPUCores float64 `json:"cpuCores"`
	MemMiB   float64 `json:"memMiB"`
	Raw      string  `json:"raw"`
}

type measureResult struct {
	Codec            string          `json:"codec"`
	EncoderMode      string          `json:"encoderMode"`
	Container        string          `json:"container"`
	ImageID          string          `json:"imageId"`
	Seconds          int             `json:"seconds"`
	Motion           string          `json:"motion"`
	WheelEvents      int             `json:"wheelEvents"`
	ScrollEventsSeen int             `json:"scrollEventsSeenByApp"`
	LiveChunks       int             `json:"liveChunksDuringSample"`
	Samples          []measureSample `json:"samples"`
	MeanCores        float64         `json:"meanCores"`
	P95Cores         float64         `json:"p95Cores"`
	MaxCores         float64         `json:"maxCores"`
	MeanMiB          float64         `json:"meanMiB"`
	MaxMiB           float64         `json:"maxMiB"`
	Limits           string          `json:"limits"`
}

// parseMiB converts a docker stats size such as "312.4MiB" or "1.2GB" to MiB.
func parseMiB(s string) (float64, error) {
	s = strings.TrimSpace(s)
	units := []struct {
		suffix string
		mul    float64
	}{{"GiB", 1024}, {"MiB", 1}, {"KiB", 1.0 / 1024}, {"GB", 1e9 / (1 << 20)}, {"MB", 1e6 / (1 << 20)},
		{"kB", 1e3 / (1 << 20)}, {"B", 1.0 / (1 << 20)}}
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			v, err := strconv.ParseFloat(strings.TrimSuffix(s, u.suffix), 64)
			return v * u.mul, err
		}
	}
	return 0, fmt.Errorf("unknown size %q", s)
}

// parseStats parses "<CPUPerc> <MemUsage>" as printed by docker stats --format '{{.CPUPerc}}|{{.MemUsage}}'.
func parseStats(line string) (cores, mib float64, err error) {
	cpu, mem, ok := strings.Cut(strings.TrimSpace(line), "|")
	if !ok {
		return 0, 0, fmt.Errorf("bad stats line %q", line)
	}
	pct, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(cpu), "%"), 64)
	if err != nil {
		return 0, 0, err
	}
	used, _, _ := strings.Cut(mem, "/")
	mib, err = parseMiB(used)
	return pct / 100, mib, err
}

func percentile(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	i := int(p*float64(len(s)-1) + 0.5)
	return s[i]
}

// runMeasure scrolls the /input scroller continuously and samples docker stats for the runner every 2 s.
func (h *harness) runMeasure() {
	if h.o.lockdown {
		return
	}
	h.waitForStartPage(30 * time.Second)
	res := &measureResult{Codec: h.o.codec, EncoderMode: "dual", Container: h.runnerName(), ImageID: h.imageID,
		Seconds: h.o.measure, Limits: "--cpus 1.5 --memory 1536m",
		Motion: "wheel dy=+/-120 px every 50 ms on #scroller of /input, direction flips every 20 events"}
	stop := make(chan struct{})
	done := make(chan int)
	go func() {
		n, dir := 0, 1.0
		for {
			select {
			case <-stop:
				done <- n
				return
			default:
			}
			h.sendInput(contract.InputEvent{T: "wheel", DY: 120 * dir, X: scrollerPoint[0], Y: scrollerPoint[1], Ts: h.ts()})
			n++
			if n%20 == 0 {
				dir = -dir
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	chunks0 := h.chunkCount()
	begin := time.Now()
	tick := time.NewTicker(2 * time.Second)
	for time.Since(begin) < time.Duration(h.o.measure)*time.Second {
		out, err := exec.Command("docker", "stats", "--no-stream", "--format", "{{.CPUPerc}}|{{.MemUsage}}", h.runnerName()).Output()
		if err == nil {
			if cores, mib, perr := parseStats(string(out)); perr == nil {
				res.Samples = append(res.Samples, measureSample{AtMs: time.Since(begin).Milliseconds(), CPUCores: cores, MemMiB: mib,
					Raw: strings.TrimSpace(string(out))})
			}
		}
		<-tick.C
	}
	tick.Stop()
	close(stop)
	res.WheelEvents = <-done
	res.LiveChunks = h.chunkCount() - chunks0
	var cpu []float64
	for _, s := range res.Samples {
		cpu = append(cpu, s.CPUCores)
		res.MeanCores += s.CPUCores
		res.MeanMiB += s.MemMiB
		res.MaxCores = max(res.MaxCores, s.CPUCores)
		res.MaxMiB = max(res.MaxMiB, s.MemMiB)
	}
	if n := float64(len(res.Samples)); n > 0 {
		res.MeanCores /= n
		res.MeanMiB /= n
	}
	res.P95Cores = percentile(cpu, 0.95)
	h.mu.Lock()
	h.measureRes = res
	h.mu.Unlock()
	h.addCheck("measure: docker stats sampled", len(res.Samples) >= h.o.measure/3, false,
		"%d samples over %ds: CPU mean %.2f p95 %.2f cores, RAM mean %.0f max %.0f MiB (%s live)",
		len(res.Samples), h.o.measure, res.MeanCores, res.P95Cores, res.MeanMiB, res.MaxMiB, h.o.codec)
}

func (h *harness) writeMeasure() {
	h.mu.Lock()
	res := h.measureRes
	h.mu.Unlock()
	if res == nil {
		return
	}
	b, _ := json.MarshalIndent(res, "", "  ")
	_ = os.WriteFile(filepath.Join(h.o.out, "measure.json"), b, 0o644)
}
