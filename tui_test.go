package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func TestScanModelFeed(t *testing.T) {
	var m tea.Model = newScanModel(nil, false)

	step := func(msg tea.Msg) { m, _ = m.Update(msg) }

	step(barBeginMsg{label: "Phase 2", total: 3})
	step(foundMsg{endpoint: "a:2408", epPing: 50 * time.Millisecond})
	step(foundMsg{endpoint: "b:2408", epPing: 20 * time.Millisecond})
	step(foundMsg{endpoint: "c:2408", epPing: 0})
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

func TestScanModelFitsWindow(t *testing.T) {
	var m tea.Model = newScanModel(nil, false)
	m, _ = m.Update(tea.WindowSizeMsg{Width: 60, Height: 20})
	m, _ = m.Update(barBeginMsg{label: "Phase 2", total: 200})
	for i := 0; i < 200; i++ {
		m, _ = m.Update(foundMsg{
			endpoint: fmt.Sprintf("1.2.3.%d:2408", i),
			epPing:   time.Duration(i) * time.Millisecond,
			exit:     fmt.Sprintf("C%d", i%9),
			colo:     fmt.Sprintf("N%d", i%9),
		})
	}

	lines := strings.Count(m.(scanModel).View(), "\n")
	if lines > 20 {
		t.Errorf("view = %d lines, want <= 20 (window height)", lines)
	}
	if lines < 10 {
		t.Errorf("view = %d lines, wastes a 20-line window", lines)
	}
}

func TestScanModelNodes(t *testing.T) {
	var m tea.Model = newScanModel(nil, false)

	step := func(msg tea.Msg) { m, _ = m.Update(msg) }

	step(foundMsg{endpoint: "a:2408", exit: "DE", colo: "FRA"})
	step(foundMsg{endpoint: "b:2408", exit: "RU", colo: "DME"})
	step(foundMsg{endpoint: "c:2408", exit: "RU", colo: "DME"})
	step(foundMsg{endpoint: "d:2408", exit: "NL", colo: "AMS", torn: true})
	step(foundMsg{endpoint: "e:2408"})

	nodes := m.(scanModel).nodes
	want := []nodeStat{{"RU", "DME", 2}, {"DE", "FRA", 1}}
	if len(nodes) != len(want) {
		t.Fatalf("nodes = %v, want %v", nodes, want)
	}
	for i := range want {
		if nodes[i] != want[i] {
			t.Errorf("nodes[%d] = %v, want %v", i, nodes[i], want[i])
		}
	}
}
