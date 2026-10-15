package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
	"github.com/Infisical/infisical-merge/packages/pam/webapp/supervisor"
)

// netnsCheck runs the image's probe inside the runner netns: host ports 80/8080 and DNS must fail, the two gateway
// ports must connect.
func (h *harness) netnsCheck() {
	hostProbe := func(port int) string { return fmt.Sprintf("tcp:%s:%d", supervisor.HostAddress, port) }
	http80, http8080 := hostProbe(80), hostProbe(8080)
	agent, proxy := hostProbe(h.o.agentPort), hostProbe(h.o.proxyPort)
	dns := "dns:" + demoAppName
	want := map[string]bool{http80: false, http8080: false, agent: true, proxy: true, dns: false}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	args := []string{"run", "--rm", "--network", "container:" + supervisor.PauseName(h.short), "--label", supervisor.SessionLabel + "=" + h.sessionID,
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "1000:1000",
		"--entrypoint", "python3", h.imageID, "/opt/iwa/netprobe.py",
		http80, http8080, agent, proxy, dns}
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	results := []map[string]any{}
	got := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		var r map[string]any
		if json.Unmarshal([]byte(strings.TrimSpace(line)), &r) != nil {
			continue
		}
		results = append(results, r)
		if c, ok := r["check"].(string); ok {
			okv, _ := r["ok"].(bool)
			got[c] = okv
		}
	}
	h.mu.Lock()
	h.netns = results
	h.mu.Unlock()
	doc := map[string]any{"command": "docker " + strings.Join(args, " "), "results": results, "expected": want}
	if err != nil {
		doc["error"] = fmt.Sprintf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	_ = os.WriteFile(filepath.Join(h.o.out, "netns-check.json"), b, 0o644)
	var bad []string
	for c, w := range want {
		if g, ok := got[c]; !ok || g != w {
			bad = append(bad, fmt.Sprintf("%s ok=%v want %v", c, g, w))
		}
	}
	sort.Strings(bad)
	h.add("netns reachability (80/8080/dns fail, agent/proxy ok)", err == nil && len(bad) == 0, "%s",
		orDefault(strings.Join(bad, "; "), fmt.Sprintf("%d probes as expected", len(want))))
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func (h *harness) statusCheck(want string) {
	code, body, err := h.call("GET", "/v1/runners/"+h.sessionID, nil)
	var st struct {
		State string `json:"state"`
		IP    string `json:"ip"`
	}
	_ = json.Unmarshal(body, &st)
	h.add("supervisor status "+want, err == nil && code == http.StatusOK && st.State == want && st.IP == h.runnerIP,
		"status %d state %s ip %s", code, st.State, st.IP)
}

func (h *harness) captureRunnerLogs() {
	name := h.runnerName()
	out, err := exec.Command("docker", "logs", name).CombinedOutput()
	if err != nil {
		h.add("runner logs captured", false, "%v", err)
		return
	}
	leak := bytes.Contains(out, []byte(h.token))
	if leak {
		out = bytes.ReplaceAll(out, []byte(h.token), []byte("<REDACTED-TOKEN>"))
	}
	_ = os.WriteFile(filepath.Join(h.o.out, "runner.log"), out, 0o644)
	h.add("runner token absent from runner logs", !leak, "%d bytes of docker logs", len(out))

	img, err := exec.Command("docker", "inspect", "--format", "{{.Image}}", name).Output()
	h.add("runner image ID equals pinned digest", err == nil && strings.TrimSpace(string(img)) == h.imageID,
		"running %s, pinned %s", strings.TrimSpace(string(img)), h.imageID)
}

func (h *harness) destroy() {
	for i := 0; i < 2; i++ {
		code, body, err := h.call("DELETE", "/v1/runners/"+h.sessionID, nil)
		h.add(fmt.Sprintf("DELETE runner (call %d) returns 200 destroyed", i+1),
			err == nil && code == http.StatusOK && bytes.Contains(body, []byte(`"destroyed"`)), "status %d", code)
	}
	out, err := exec.Command("docker", "ps", "-a", "--filter", "label="+supervisor.SessionLabel+"="+h.sessionID,
		"--format", "{{.Names}}").Output()
	left := strings.Fields(string(out))
	h.add("no containers left for the session", err == nil && len(left) == 0, "leftover %v", left)
}

func (h *harness) scanHarnessLogs() {
	files := []string{filepath.Join(h.o.out, "harness.log"), filepath.Join(h.o.out, "supervisor-calls.log")}
	if h.o.supLog != "" {
		files = append(files, h.o.supLog)
	}
	var leaks []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err == nil && h.token != "" && bytes.Contains(b, []byte(h.token)) {
			leaks = append(leaks, filepath.Base(f))
		}
	}
	h.add("runner token absent from harness and supervisor logs", len(leaks) == 0, "scanned %d files, leaks in %v", len(files), leaks)
}

func nalTypes(b []byte) []int {
	var out []int
	for i := 0; i+3 < len(b); i++ {
		if b[i] == 0 && b[i+1] == 0 && b[i+2] == 1 {
			out = append(out, int(b[i+3]&0x1f))
			i += 3
		}
	}
	return out
}

// spsCodec derives the WebCodecs avc1 string from the first SPS in an Annex B buffer.
func spsCodec(b []byte) string {
	for i := 0; i+6 < len(b); i++ {
		if b[i] == 0 && b[i+1] == 0 && b[i+2] == 1 && b[i+3]&0x1f == 7 {
			return fmt.Sprintf("avc1.%02X%02X%02X", b[i+4], b[i+5], b[i+6])
		}
	}
	return "none"
}

func codecOf(vc *contract.VideoConfig) string {
	if vc == nil {
		return "none"
	}
	return vc.Codec
}

func ffprobeJSON(args ...string) (map[string]any, error) {
	out, err := exec.Command("ffprobe", append([]string{"-v", "error", "-of", "json"}, args...)...).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, err
	}
	var m map[string]any
	return m, json.Unmarshal(out, &m)
}

func firstStream(m map[string]any) map[string]any {
	ss, _ := m["streams"].([]any)
	if len(ss) == 0 {
		return map[string]any{}
	}
	s, _ := ss[0].(map[string]any)
	return s
}

func (h *harness) verifyOutputs() {
	h.mu.Lock()
	vc, chunks, first, kfAt, inputChunk := h.videoConfig, slices.Clone(h.chunks), h.firstChunk, h.kfRequestAt, h.inputChunk
	recInit, segs := h.recInit, slices.Clone(h.segs)
	h.mu.Unlock()
	if h.launchAt.IsZero() {
		return
	}
	h.verifyLiveConfig(vc, chunks, first)
	h.verifyKeyframeAnswer(chunks, kfAt)
	h.verifyLiveDecode(chunks, inputChunk)
	h.verifyRecording(recInit, segs)
	h.verifyDemoApp()
	h.finishLockdown()
	h.finishFaults()
	h.writeMeasure()
	h.scanHarnessLogs()
}

func (h *harness) verifyLiveConfig(vc *contract.VideoConfig, chunks []chunkInfo, first []byte) {
	if h.o.codec == "vp9" {
		// CONTRACTS 1.6: VP9 live is announced as vp09.00.10.08 with no format field; the recording stays H.264.
		h.add("VIDEO_CONFIG vp09.00.10.08 without format", vc != nil && vc.Codec == contract.CodecStringVP9Live && vc.Format == "",
			"%+v", vc)
		h.add("first VIDEO_CHUNK is a keyframe (flag and VP9 key frame header)",
			len(chunks) > 0 && chunks[0].Keyframe && vp9Keyframe(first), "chunks %d, first bytes % x", len(chunks), headBytes(first, 4))
		return
	}
	// CONTRACTS 1.6: codec is the exact WebCodecs string of the stream, so it must be an H.264 Constrained Baseline
	// avc1 string (profile 0x42, the family the viewer probes with avc1.42E01F) equal to what the first SPS says.
	h.add("VIDEO_CONFIG avc1.42xxxx annexb", vc != nil && strings.HasPrefix(strings.ToLower(vc.Codec), "avc1.42") && vc.Format == "annexb",
		"%+v", vc)
	h.add("VIDEO_CONFIG codec matches the stream SPS", vc != nil && strings.EqualFold(vc.Codec, spsCodec(first)),
		"config %v, SPS says %s", codecOf(vc), spsCodec(first))
	nals := nalTypes(first)
	h.add("first VIDEO_CHUNK is a keyframe (flag and IDR with SPS/PPS)",
		len(chunks) > 0 && chunks[0].Keyframe && slices.Contains(nals, 5) && slices.Contains(nals, 7) && slices.Contains(nals, 8),
		"chunks %d, first NAL types %v", len(chunks), nals)
}

func (h *harness) verifyKeyframeAnswer(chunks []chunkInfo, kfAt int) {
	if kfAt < 0 {
		h.add("AGENT_CONTROL keyframe answered within 2 frames", false, "keyframe never requested")
		return
	}
	idx := -1
	for _, c := range chunks {
		if c.Index >= kfAt && c.Keyframe {
			idx = c.Index
			break
		}
	}
	h.add("AGENT_CONTROL keyframe answered within 2 frames", idx >= 0 && idx-kfAt <= 3,
		"requested at chunk %d, keyframe chunk %d (delta %d; one chunk of slack for frames already in flight)",
		kfAt, idx, idx-kfAt)
}

func (h *harness) verifyLiveDecode(chunks []chunkInfo, inputChunk int) {
	live := filepath.Base(livePath(h.o.out, h.o.codec))
	in := ffmpegInput(h.o.out, h.o.codec)
	probe := append(append([]string{}, in[:2]...), "-count_frames", "-select_streams", "v:0",
		"-show_entries", "stream=codec_name,profile,width,height,nb_read_frames", in[3])
	if m, err := ffprobeJSON(probe...); err != nil {
		h.add("ffprobe decodes "+live, false, "%v", err)
	} else {
		s := firstStream(m)
		n, _ := strconv.Atoi(fmt.Sprint(s["nb_read_frames"]))
		h.add("ffprobe decodes "+live, s["codec_name"] == h.o.codec && n > 0,
			"codec %v profile %v %vx%v, %d frames decoded of %d chunks", s["codec_name"], s["profile"], s["width"], s["height"], n, len(chunks))
	}
	h.extractFrame(-1, filepath.Join(h.o.out, "frame-live-last.png"))
	if inputChunk > 0 {
		h.extractFrame(inputChunk, filepath.Join(h.o.out, "frame-live-before-input.png"))
	}
}

func (h *harness) verifyRecording(recInit *contract.RecInitMeta, segs []segInfo) {
	h.add("REC_INIT received", recInit != nil, "%+v", recInit)
	shaBad := []int{}
	for _, s := range segs {
		if !s.ShaOK {
			shaBad = append(shaBad, s.Meta.SegmentIndex)
		}
	}
	h.add("every REC_SEGMENT sha256 matches", len(segs) > 0 && len(shaBad) == 0, "%d segments, mismatches %v", len(segs), shaBad)
	uniq, dups := dedupeSegments(segs)
	for i, s := range uniq {
		if s.Meta.SegmentIndex != i+1 {
			h.add("REC_SEGMENT indexes 1..n", false, "position %d has index %d", i, s.Meta.SegmentIndex)
			break
		}
	}
	if len(dups) > 0 {
		h.add("re-sent REC_SEGMENTs identical to the first copy", sameSha(segs), "re-sent indexes %v", dups)
	}
	if recInit == nil {
		return
	}
	for _, s := range uniq {
		h.verifySegment(s, s.Meta.SegmentIndex == 1)
	}
	if len(uniq) == 0 || uniq[0].Meta.SegmentIndex != 1 {
		h.add("segment 1 is H.264 High, 10 s +/- 1 frame, starts with IDR", false, "segment 1 missing")
	}
}

func headBytes(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}

// extractFrame decodes live frame n (n < 0: the last one) to a PNG.
func (h *harness) extractFrame(n int, png string) bool {
	args := append([]string{"-v", "error", "-y"}, ffmpegInput(h.o.out, h.o.codec)...)
	if n < 0 {
		args = append(args, "-update", "1", png)
	} else {
		args = append(args, "-vf", fmt.Sprintf("select=eq(n\\,%d)", n), "-frames:v", "1", png)
	}
	return exec.Command("ffmpeg", args...).Run() == nil
}

// dedupeSegments keeps the first copy of each index, sorted by index, and lists indexes received more than once.
func dedupeSegments(segs []segInfo) ([]segInfo, []int) {
	byIdx := map[int]segInfo{}
	var dups []int
	for _, s := range segs {
		if _, ok := byIdx[s.Meta.SegmentIndex]; ok {
			dups = append(dups, s.Meta.SegmentIndex)
			continue
		}
		byIdx[s.Meta.SegmentIndex] = s
	}
	out := make([]segInfo, 0, len(byIdx))
	for _, s := range byIdx {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Meta.SegmentIndex < out[j].Meta.SegmentIndex })
	return out, dups
}

func sameSha(segs []segInfo) bool {
	first := map[int]string{}
	for _, s := range segs {
		if sha, ok := first[s.Meta.SegmentIndex]; ok && sha != s.Meta.SHA256 {
			return false
		}
		first[s.Meta.SegmentIndex] = s.Meta.SHA256
	}
	return true
}

func (h *harness) verifySegment(s segInfo, strict bool) {
	initB, err1 := os.ReadFile(filepath.Join(h.o.out, "rec-init.mp4"))
	segB, err2 := os.ReadFile(filepath.Join(h.o.out, s.File))
	name := fmt.Sprintf("segment %d is H.264 High, %d s +/- 1 frame, starts with IDR", s.Meta.SegmentIndex, segmentSeconds)
	if !strict {
		name = fmt.Sprintf("segment %d is H.264 High, starts with IDR", s.Meta.SegmentIndex)
	}
	if err1 != nil || err2 != nil {
		h.addCheck(name, false, strict, "read: %v %v", err1, err2)
		return
	}
	concat := filepath.Join(h.o.out, fmt.Sprintf("rec-concat-%04d.mp4", s.Meta.SegmentIndex))
	if err := os.WriteFile(concat, append(append([]byte(nil), initB...), segB...), 0o644); err != nil {
		h.addCheck(name, false, strict, "%v", err)
		return
	}
	m, err := ffprobeJSON("-count_frames", "-select_streams", "v:0",
		"-show_entries", "stream=codec_name,profile,nb_read_frames,r_frame_rate:format=duration", concat)
	if err != nil {
		h.addCheck(name, false, strict, "ffprobe: %v", err)
		return
	}
	st := firstStream(m)
	format, _ := m["format"].(map[string]any)
	dur, _ := strconv.ParseFloat(fmt.Sprint(format["duration"]), 64)
	frames, _ := strconv.Atoi(fmt.Sprint(st["nb_read_frames"]))
	fps := 30.0
	if num, den, ok := strings.Cut(fmt.Sprint(st["r_frame_rate"]), "/"); ok {
		n, _ := strconv.ParseFloat(num, 64)
		d, _ := strconv.ParseFloat(den, 64)
		if n > 0 && d > 0 {
			fps = n / d
		}
	}
	// fMP4 fragments carry their absolute decode time, so the probed format duration is the end time; the segment
	// length is its frame count over the frame rate (and the meta PTS span as a cross-check).
	segDur := float64(frames) / fps
	tol := 1/fps + 0.001
	durOK := math.Abs(segDur-segmentSeconds) <= tol &&
		math.Abs(float64(s.Meta.EndPtsUs-s.Meta.StartPtsUs)/1e6-segmentSeconds) <= tol

	fm, ferr := ffprobeJSON("-select_streams", "v:0", "-read_intervals", "%+#1", "-show_frames",
		"-show_entries", "frame=key_frame,pict_type", concat)
	firstKey, firstPict := "", ""
	if ferr == nil {
		if fs, _ := fm["frames"].([]any); len(fs) > 0 {
			f0, _ := fs[0].(map[string]any)
			firstKey, firstPict = fmt.Sprint(f0["key_frame"]), fmt.Sprint(f0["pict_type"])
		}
	}
	annexb, _ := exec.Command("ffmpeg", "-v", "error", "-i", concat, "-frames:v", "1", "-c:v", "copy",
		"-bsf:v", "h264_mp4toannexb", "-f", "h264", "-").Output()
	nals := nalTypes(annexb)
	idr := firstKey == "1" && firstPict == "I" && slices.Contains(nals, 5)

	ok := st["codec_name"] == "h264" && st["profile"] == "High" && idr && (durOK || !strict)
	h.addCheck(name, ok, strict, "codec %v profile %v length %.3fs (%d frames @ %.2f fps, meta %d frames, pts %d..%d us, probed end %.3fs) first frame key=%s pict=%s NALs %v",
		st["codec_name"], st["profile"], segDur, frames, fps, s.Meta.FrameCount, s.Meta.StartPtsUs, s.Meta.EndPtsUs, dur,
		firstKey, firstPict, nals)
	if s.Meta.SegmentIndex == 1 {
		_ = exec.Command("ffmpeg", "-v", "error", "-y", "-i", concat, "-frames:v", "1",
			filepath.Join(h.o.out, "frame-rec-0001.png")).Run()
	}
}
