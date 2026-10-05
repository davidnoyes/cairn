//go:build !e2eclock

package main

import (
	"testing"

	"github.com/aloisdeniel/cairn/internal/clock"
)

func TestServeClockIsTheWallClock(t *testing.T) {
	clk, err := serveClock()
	if _, ok := clk.(clock.Real); !ok || err != nil {
		t.Errorf("serveClock() = %T, %v; want clock.Real", clk, err)
	}
}
