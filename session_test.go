package main

import (
	"sync"
	"testing"
)

func TestSessionTableLifecycle(t *testing.T) {
	table := NewSessionTable()
	s := newSession(1, "example.com:443", nil)

	if err := table.Add(s); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := table.Add(s); err == nil {
		t.Fatal("adding the same id twice must fail")
	}
	if table.Count() != 1 {
		t.Fatalf("Count = %d, want 1", table.Count())
	}
	if _, ok := table.Get(1); !ok {
		t.Fatal("Get(1) not found after Add")
	}

	table.Delete(1)
	if table.Count() != 0 {
		t.Fatalf("Count after Delete = %d, want 0", table.Count())
	}
	if !s.IsClosed() {
		t.Fatal("session must be closed by Delete")
	}
	select {
	case <-s.Done():
	default:
		t.Fatal("Done() channel must be closed after teardown")
	}
	// Delete of a missing id is a no-op, not a panic.
	table.Delete(1)
}

func TestSessionTeardownIsIdempotent(t *testing.T) {
	s := newSession(9, "example.com:443", nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.teardown()
			s.teardown()
		}()
	}
	wg.Wait()
	if !s.IsClosed() {
		t.Fatal("session should be closed")
	}
	// The CLOSE notification must be reported exactly once.
	if !s.NotifyClose() {
		t.Fatal("first NotifyClose should claim the notification")
	}
	if s.NotifyClose() {
		t.Fatal("second NotifyClose must be false")
	}
}

func TestSessionInfoSnapshot(t *testing.T) {
	s := newSession(3, "example.com:443", nil)
	s.setState(SessionOpen)
	s.AddUp(100)
	s.AddDown(200)

	info := s.Info()
	if info.ID != 3 || info.Target != "example.com:443" {
		t.Errorf("unexpected info: %+v", info)
	}
	if info.State != "open" {
		t.Errorf("state = %q, want open", info.State)
	}
	if info.BytesUp != 100 || info.BytesDown != 200 {
		t.Errorf("counters = %d/%d, want 100/200", info.BytesUp, info.BytesDown)
	}
	if info.UDP {
		t.Error("tcp session reported as UDP")
	}
}

func TestSessionTableSnapshotAndCloseAll(t *testing.T) {
	table := NewSessionTable()
	for i := uint32(1); i <= 3; i++ {
		if err := table.Add(newSession(i, "example.com:443", nil)); err != nil {
			t.Fatalf("Add(%d): %v", i, err)
		}
	}
	if len(table.Snapshot()) != 3 {
		t.Fatalf("Snapshot = %d entries, want 3", len(table.Snapshot()))
	}
	table.CloseAll()
	if table.Count() != 0 {
		t.Fatalf("Count after CloseAll = %d, want 0", table.Count())
	}
}
