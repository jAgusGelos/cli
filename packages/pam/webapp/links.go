package webapp

import (
	"encoding/json"
	"net"
	"sync"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
)

// agentLink is the gateway side of the runner agent connection. Writes are serialized and carry the gateway->agent
// seq counter (CONTRACTS.md 1.2).
type agentLink struct {
	conn  net.Conn
	hello contract.AgentHello
	start time.Time

	mu  sync.Mutex
	seq uint32

	// done is closed when readAgent stops reading this link, so every frame the agent sent before closing it has
	// been handled.
	done chan struct{}
}

func newAgentLink(c net.Conn, hello contract.AgentHello) *agentLink {
	return &agentLink{conn: c, hello: hello, start: time.Now(), done: make(chan struct{})}
}

func (a *agentLink) send(t contract.FrameType, payload []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	f := &contract.Frame{Type: t, Seq: a.seq, TimestampUs: uint64(time.Since(a.start).Microseconds()), Payload: payload}
	a.seq++
	_ = a.conn.SetWriteDeadline(time.Now().Add(linkWriteTimeout))
	return contract.WriteFrame(a.conn, f)
}

func (a *agentLink) sendJSON(t contract.FrameType, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return a.send(t, b)
}

func (a *agentLink) welcome() error {
	w := contract.AgentWelcome{OK: true}
	w.Recording = &struct {
		SegmentSeconds int `json:"segmentSeconds"`
	}{SegmentSeconds: defaultRecording.SegmentSeconds}
	return a.sendJSON(contract.FrameAgentWelcome, w)
}

func (a *agentLink) control(c contract.AgentControl) error {
	return a.sendJSON(contract.FrameAgentControl, c)
}

func (a *agentLink) extCommand(c contract.ExtCommand) error {
	return a.sendJSON(contract.FrameExtCommand, c)
}

// viewerLink owns the downstream writes to the viewer tunnel. A single writer goroutine keeps frames in order and the
// viewer-link seq counter (rewritten on forwarded VIDEO_* frames) is assigned at enqueue time under the lock, so the
// agent reader never blocks on a slow viewer: video frames are dropped when the queue is full.
type viewerLink struct {
	conn  net.Conn
	start time.Time

	mu      sync.Mutex
	seq     uint32
	out     chan []byte
	dead    chan struct{}
	deadErr sync.Once
	drained chan struct{}
	closing bool
}

const viewerQueue = 512

func newViewerLink(c net.Conn) *viewerLink {
	v := &viewerLink{conn: c, start: time.Now(), out: make(chan []byte, viewerQueue), dead: make(chan struct{}), drained: make(chan struct{})}
	go v.writer()
	return v
}

func (v *viewerLink) writer() {
	defer close(v.drained)
	for b := range v.out {
		_ = v.conn.SetWriteDeadline(time.Now().Add(linkWriteTimeout))
		if _, err := v.conn.Write(b); err != nil {
			v.kill()
			for range v.out {
			}
			return
		}
	}
}

func (v *viewerLink) kill() {
	v.deadErr.Do(func() {
		close(v.dead)
		v.conn.Close()
	})
}

// enqueue assigns the next seq and queues the frame. droppable frames are refused when the queue is full; others wait
// up to viewerEnqueueWait, then the link is considered dead.
func (v *viewerLink) enqueue(f *contract.Frame, droppable bool) (uint32, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closing {
		return 0, false
	}
	select {
	case <-v.dead:
		return 0, false
	default:
	}
	f.Seq = v.seq
	if f.Type != contract.FrameVideoChunk && f.Type != contract.FrameVideoConfig {
		f.TimestampUs = uint64(time.Since(v.start).Microseconds())
	}
	b := f.Marshal()
	if droppable {
		select {
		case v.out <- b:
		default:
			return 0, false
		}
	} else {
		select {
		case v.out <- b:
		case <-v.dead:
			return 0, false
		case <-time.After(viewerEnqueueWait):
			go v.kill()
			return 0, false
		}
	}
	v.seq++
	return f.Seq, true
}

func (v *viewerLink) control(c contract.ControlDown) bool {
	b, err := json.Marshal(c)
	if err != nil {
		return false
	}
	_, ok := v.enqueue(&contract.Frame{Type: contract.FrameControl, Payload: b}, false)
	return ok
}

func (v *viewerLink) controlError(code, msg string, fatal bool) bool {
	return v.control(contract.ControlDown{Kind: contract.ControlError, Code: code, Message: msg, Fatal: &fatal})
}

// fatalError sends a fatal CONTROL error whose message is its code.
func (v *viewerLink) fatalError(code string) bool {
	return v.controlError(code, code, true)
}

// close flushes queued frames for at most wait, then closes the connection.
func (v *viewerLink) close(wait time.Duration) {
	v.mu.Lock()
	if !v.closing {
		v.closing = true
		close(v.out)
	}
	v.mu.Unlock()
	select {
	case <-v.drained:
	case <-time.After(wait):
	}
	v.kill()
}
