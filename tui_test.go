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

	m, _ = m.Update(tea.WindowSizeMsg{Width: 60, Height: 60})
	if rows := strings.Count(m.(scanModel).View(), ":2408"); rows != feedMax {
		t.Errorf("feed = %d rows in a tall window, want the %d cap", rows, feedMax)
	}
}

func TestScanModelExpandFeed(t *testing.T) {
	var m tea.Model = newScanModel(nil, false)
	m, _ = m.Update(tea.WindowSizeMsg{Width: 70, Height: 20})
	m, _ = m.Update(stepMsg{done: true, label: "Phase 1", summary: "2408"})
	m, _ = m.Update(barBeginMsg{label: "Phase 2", total: 200})
	for i := 0; i < 60; i++ {
		m, _ = m.Update(foundMsg{
			endpoint: fmt.Sprintf("1.2.3.%d:2408", i),
			epPing:   time.Duration(i) * time.Millisecond,
			exit:     "DE",
			colo:     "FRA",
		})
	}

	before := strings.Count(m.(scanModel).View(), "\n")
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'f'}})
	v := m.(scanModel).View()

	if strings.Contains(v, "NODES") || strings.Contains(v, "Phase 1") {
		t.Error("f should leave the feed alone on screen")
	}
	if rows := strings.Count(v, ":2408"); rows <= 9 {
		t.Errorf("feed = %d rows after f, want more than the 9 it had", rows)
	}
	if lines := strings.Count(v, "\n"); lines > 20 || lines != before {
		t.Errorf("view = %d lines after f, want %d (window height)", lines, before)
	}
}

func TestScanModelDropsFeedOnDone(t *testing.T) {
	sm := newScanModel(nil, false)
	sm.dropLists = true
	var m tea.Model = sm
	m, _ = m.Update(tea.WindowSizeMsg{Width: 70, Height: 30})
	m, _ = m.Update(foundMsg{endpoint: "1.2.3.4:2408", exit: "DE", colo: "FRA"})
	m, _ = m.Update(barEndMsg{label: "Phase 2", summary: "done"})
	m, _ = m.Update(doneMsg{})

	v := m.(scanModel).View()
	if strings.Contains(v, ":2408") {
		t.Error("the feed should go once the console tables repeat it")
	}
	if !strings.Contains(v, "NODES") || !strings.Contains(v, "Phase 2") {
		t.Error("the node panel and the phase lines should stay")
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
