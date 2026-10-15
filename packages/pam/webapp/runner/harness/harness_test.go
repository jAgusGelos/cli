package main

import (
	"bytes"
	"math"
	"testing"
)

func TestVP9Keyframe(t *testing.T) {
	if !vp9Keyframe([]byte{0x82, 0x49, 0x83, 0x42, 0x00}) {
		t.Fatal("profile 0 keyframe not detected")
	}
	if vp9Keyframe([]byte{0x86, 0x00, 0x00, 0x00}) {
		t.Fatal("inter frame reported as keyframe")
	}
}

func TestIVFHeader(t *testing.T) {
	b := ivfHeader(1280, 720, 30, 7)
	if len(b) != 32 || !bytes.Equal(b[:4], []byte("DKIF")) || !bytes.Equal(b[8:12], []byte("VP90")) || b[24] != 7 {
		t.Fatalf("bad header % x", b)
	}
}

func TestCharKey(t *testing.T) {
	for r, want := range map[rune]struct {
		code  string
		shift bool
	}{'a': {"KeyA", false}, 'S': {"KeyS", true}, ':': {"Semicolon", true}, '/': {"Slash", false}, '-': {"Minus", false}} {
		code, shift := charKey(r)
		if code != want.code || shift != want.shift {
			t.Errorf("%q: got %s %v", r, code, shift)
		}
	}
}

func TestParseStats(t *testing.T) {
	cores, mib, err := parseStats("89.5%|1.5GiB / 1.5GiB\n")
	if err != nil || math.Abs(cores-0.895) > 1e-9 || mib != 1536 {
		t.Fatalf("got %v %v %v", cores, mib, err)
	}
}

func TestExtensionsOK(t *testing.T) {
	ok, found := extensionsOK(profileExtensions + "/" + infisicalExtensionID + "/1.0\n" + profileExtensions + "/abc/1\n")
	if ok || len(found) != 1 || found[0] != "abc" {
		t.Fatalf("got %v %v", ok, found)
	}
	if ok, _ := extensionsOK("ls: cannot access: No such file or directory"); !ok {
		t.Fatal("missing dir should be ok")
	}
}
