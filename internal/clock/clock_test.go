package clock

import (
	"testing"
	"time"
)

func TestRealIsNow(t *testing.T) {
	before := time.Now()
	got := Real{}.Now()
	if got.Before(before) || got.After(time.Now()) {
		t.Errorf("Real.Now() = %v, not between calls to time.Now", got)
	}
}

func TestFakeAdvanceAndSet(t *testing.T) {
	start := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	f := NewFake(start)
	if !f.Now().Equal(start) {
		t.Fatalf("Now() = %v, want %v", f.Now(), start)
	}
	f.Advance(14 * 24 * time.Hour)
	if want := start.AddDate(0, 0, 14); !f.Now().Equal(want) {
		t.Errorf("after Advance: %v, want %v", f.Now(), want)
	}
	f.Set(start)
	if !f.Now().Equal(start) {
		t.Errorf("after Set: %v, want %v", f.Now(), start)
	}
	var _ Clock = f
	var _ Clock = Real{}
}
