package webapp

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/contract"
	"github.com/stretchr/testify/require"
)

type shortcutVector struct {
	Name         string                `json:"name"`
	Events       []contract.InputEvent `json:"events"`
	Kept         []contract.InputEvent `json:"kept"`
	DroppedRules []string              `json:"droppedRules"`
}

// Every F0 shortcut vector gives the same kept and dropped lists through the gateway input path, and the L3 record
// carries the dropped rules.
func TestInputPathShortcutVectors(t *testing.T) {
	raw, err := os.ReadFile("contract/testdata/shortcuts.json")
	require.NoError(t, err)
	var vectors []shortcutVector
	require.NoError(t, json.Unmarshal(raw, &vectors))
	require.NotEmpty(t, vectors)
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			p := newInputPath(1280, 720)
			payload, _ := json.Marshal(contract.InputBatch{Events: v.Events})
			kept, rec, _, err := p.process(payload, 7, time.Now())
			require.NoError(t, err)
			if len(v.Kept) == 0 {
				require.Empty(t, kept)
			} else {
				require.Equal(t, v.Kept, kept)
			}
			var rules []string
			if rec != nil {
				for _, d := range rec.Dropped {
					rules = append(rules, d.Rule)
				}
				require.Equal(t, uint32(7), rec.FrameSeq)
			}
			if len(v.DroppedRules) == 0 {
				require.Empty(t, rules)
			} else {
				require.Equal(t, v.DroppedRules, rules)
			}
		})
	}
}

func TestInputPathMalformedAndCoalescing(t *testing.T) {
	p := newInputPath(1280, 720)
	now := time.Now()
	bad := [][]byte{
		[]byte(`not json`),
		[]byte(`{"events":[{"t":"teleport"}]}`),
		[]byte(`{"events":[{"t":"move","x":1280,"y":10}]}`),
		[]byte(`{"events":[{"t":"key","action":"down"}]}`),
		[]byte(`{"events":[{"t":"button","action":"down","button":0,"x":-1,"y":0}]}`),
	}
	for i, b := range bad {
		kept, rec, tooMany, err := p.process(b, uint32(i), now.Add(time.Duration(i)*time.Second))
		require.ErrorIs(t, err, errMalformed)
		require.Nil(t, kept)
		require.Equal(t, "malformed", rec.Dropped[0].Rule)
		require.Equal(t, i == len(bad)-1, tooMany, "frame %d", i)
	}
	// The malformed window slides: 11 s later the counter starts over.
	_, _, tooMany, err := p.process([]byte(`x`), 9, now.Add(20*time.Second))
	require.ErrorIs(t, err, errMalformed)
	require.False(t, tooMany)

	// Moves are injected but recorded at most once per 100 ms; the last move of a frame wins.
	p = newInputPath(1280, 720)
	moves := []byte(`{"events":[{"t":"move","x":1,"y":1},{"t":"move","x":2,"y":2}]}`)
	kept, rec, _, err := p.process(moves, 1, now)
	require.NoError(t, err)
	require.Len(t, kept, 2)
	require.Len(t, rec.Events, 1)
	require.Equal(t, 2, rec.Events[0].X)
	kept, rec, _, err = p.process(moves, 2, now.Add(50*time.Millisecond))
	require.NoError(t, err)
	require.Len(t, kept, 2)
	require.Nil(t, rec, "coalesced moves only: nothing to record")

	// Paste is blocked with clipboard off and recorded with its size; buttons above 2 are dropped by the filter.
	kept, rec, _, err = p.process([]byte(`{"events":[{"t":"paste","id":"u1","part":0,"total":1,"text":"hello"},{"t":"button","action":"down","button":3,"x":5,"y":5}]}`), 3, now.Add(time.Second))
	require.NoError(t, err)
	require.Empty(t, kept)
	require.Equal(t, "paste_blocked", rec.Dropped[0].T)
	require.Equal(t, 5, *rec.Dropped[0].Bytes)
	require.Equal(t, "Button>2", rec.Dropped[1].Rule)
}
