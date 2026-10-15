package main

import (
	"encoding/binary"
	"os"
	"path/filepath"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
)

// liveWriter stores the live VIDEO_CHUNK stream in a file ffprobe and ffmpeg can read: raw Annex B for H.264, IVF
// for VP9 (one IVF frame per chunk, 1/framerate time base).
type liveWriter interface {
	Configure(vc contract.VideoConfig)
	WriteChunk(b []byte) error
	Close() error
}

func livePath(out, codec string) string {
	if codec == "vp9" {
		return filepath.Join(out, "live.ivf")
	}
	return filepath.Join(out, "live.h264")
}

func ffmpegInput(out, codec string) []string {
	if codec == "vp9" {
		return []string{"-f", "ivf", "-i", livePath(out, codec)}
	}
	return []string{"-f", "h264", "-i", livePath(out, codec)}
}

func newLiveWriter(out, codec string) (liveWriter, error) {
	f, err := os.Create(livePath(out, codec))
	if err != nil {
		return nil, err
	}
	if codec == "vp9" {
		return &ivfWriter{f: f, width: 1280, height: 720, rate: 30}, nil
	}
	return annexBWriter{f}, nil
}

type annexBWriter struct{ f *os.File }

func (w annexBWriter) Configure(contract.VideoConfig) {}
func (w annexBWriter) WriteChunk(b []byte) error      { _, err := w.f.Write(b); return err }
func (w annexBWriter) Close() error                   { return w.f.Close() }

type ivfWriter struct {
	f             *os.File
	width, height int
	rate          int
	frames        uint32
	headerDone    bool
}

func ivfHeader(width, height, rate int, frames uint32) []byte {
	b := make([]byte, 32)
	copy(b[0:4], "DKIF")
	binary.LittleEndian.PutUint16(b[4:], 0)
	binary.LittleEndian.PutUint16(b[6:], 32)
	copy(b[8:12], "VP90")
	binary.LittleEndian.PutUint16(b[12:], uint16(width))
	binary.LittleEndian.PutUint16(b[14:], uint16(height))
	binary.LittleEndian.PutUint32(b[16:], uint32(rate))
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint32(b[24:], frames)
	return b
}

func ivfFrameHeader(size int, pts uint64) []byte {
	b := make([]byte, 12)
	binary.LittleEndian.PutUint32(b[0:], uint32(size))
	binary.LittleEndian.PutUint64(b[4:], pts)
	return b
}

func (w *ivfWriter) Configure(vc contract.VideoConfig) {
	if w.headerDone {
		return
	}
	if vc.Width > 0 && vc.Height > 0 {
		w.width, w.height = vc.Width, vc.Height
	}
	if vc.Framerate > 0 {
		w.rate = vc.Framerate
	}
}

func (w *ivfWriter) WriteChunk(b []byte) error {
	if !w.headerDone {
		if _, err := w.f.Write(ivfHeader(w.width, w.height, w.rate, 0)); err != nil {
			return err
		}
		w.headerDone = true
	}
	if _, err := w.f.Write(ivfFrameHeader(len(b), uint64(w.frames))); err != nil {
		return err
	}
	w.frames++
	_, err := w.f.Write(b)
	return err
}

func (w *ivfWriter) Close() error {
	if w.headerDone {
		_, _ = w.f.WriteAt(ivfHeader(w.width, w.height, w.rate, w.frames), 0)
	}
	return w.f.Close()
}

// vp9Keyframe reports whether a VP9 frame (or the first frame of a superframe) is a profile 0 keyframe: frame
// marker 2, profile 0, show_existing_frame 0, frame_type 0, followed by the sync code 0x49 0x83 0x42.
func vp9Keyframe(b []byte) bool {
	if len(b) < 4 || b[0]&0xC0 != 0x80 {
		return false
	}
	profile := (b[0]>>5)&1 | (b[0]>>4)&1<<1
	if profile != 0 || b[0]&0x08 != 0 || b[0]&0x04 != 0 {
		return false
	}
	return b[1] == 0x49 && b[2] == 0x83 && b[3] == 0x42
}
