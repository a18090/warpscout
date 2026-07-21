package main

import (
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func TestScanModelFeed(t *testing.T) {
	var m tea.Model = newScanModel(nil, false)

	step := func(msg tea.Msg) { m, _ = m.Update(msg) }

	step(barBeginMsg{label: "Phase 2", total: 3})
	step(foundMsg{endpoint: "a:2408", latency: 50 * time.Millisecond})
	step(foundMsg{endpoint: "b:2408", latency: 20 * time.Millisecond})
	step(foundMsg{endpoint: "c:2408", latency: 0})
	step(probedMsg{})
	step(probedMsg{})
	step(probedMsg{})

	sm := m.(scanModel)
	if got := []string{sm.feed[0].endpoint, sm.feed[1].endpoint, sm.feed[2].endpoint}; got[0] != "b:2408" || got[1] != "a:2408" || got[2] != "c:2408" {
		t.Errorf("feed order = %v, want [b a c] (by ping, unknown last)", got)
	}
	if sm.done != 3 {
		t.Errorf("probed = %d, want 3", sm.done)
	}
	if sm.finished {
		t.Error("model finished before doneMsg")
	}

	step(doneMsg{})
	if !m.(scanModel).finished {
		t.Error("doneMsg should mark the model finished")
	}
}
