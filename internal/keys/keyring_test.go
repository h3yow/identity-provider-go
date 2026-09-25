package keys

import (
	"errors"
	"testing"
	"time"
)

func TestKeyRotationLifecycle(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	r := NewKeyRing()

	v1, err := r.Rotate("v1", []byte("secret-1"), t0, time.Hour, 2*time.Hour)
	if err != nil {
		t.Fatalf("rotate v1: %v", err)
	}
	if got := r.ActiveID(); got != "v1" {
		t.Fatalf("active id = %q, want v1", got)
	}
	// A second rotation adds a coexisting version; v1 is retained.
	v2, err := r.Rotate("v2", []byte("secret-2"), t0.Add(30*time.Minute), time.Hour, 2*time.Hour)
	if err != nil {
		t.Fatalf("rotate v2: %v", err)
	}
	if got := r.ActiveID(); got != "v2" {
		t.Fatalf("active id after rotation = %q, want v2", got)
	}
	if ids := r.IDs(); len(ids) != 2 || ids[0] != "v1" || ids[1] != "v2" {
		t.Fatalf("versions = %v, want [v1 v2]", ids)
	}

	cases := []struct {
		name  string
		id    string
		now   time.Time
		state State
	}{
		{"v1 active before its expiry", "v1", t0.Add(30 * time.Minute), StateActive},
		{"v2 active before its expiry", "v2", t0.Add(80 * time.Minute), StateActive},
		{"v1 in grace after signing expiry", "v1", t0.Add(90 * time.Minute), StateGrace},
		{"v1 retired after retire deadline", "v1", t0.Add(181 * time.Minute), StateRetired},
		{"v2 in grace after its expiry", "v2", t0.Add(91 * time.Minute), StateGrace},
		{"v2 retired", "v2", t0.Add(211 * time.Minute), StateRetired},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := r.State(c.id, c.now)
			if err != nil {
				t.Fatalf("State: %v", err)
			}
			t.Logf("input id=%s now=%s => state=%s (ExpiresAt=%s RetireAt=%s)",
				c.id, c.now.Format(time.RFC3339), got,
				func() time.Time {
					if c.id == "v1" {
						return v1.ExpiresAt
					}
					return v2.ExpiresAt
				}().Format(time.RFC3339),
				func() time.Time {
					if c.id == "v1" {
						return v1.RetireAt
					}
					return v2.RetireAt
				}().Format(time.RFC3339))
			if got != c.state {
				t.Fatalf("state = %s, want %s", got, c.state)
			}
		})
	}
}

func TestActiveRefusesExpiredSigningKey(t *testing.T) {
	t0 := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	r := NewKeyRing()
	if _, err := r.Rotate("v1", []byte("s"), t0, time.Hour, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	_, err := r.Active(t0.Add(61 * time.Minute))
	if !errors.Is(err, ErrNotActive) {
		t.Fatalf("expected ErrNotActive, got %v", err)
	}
	t.Logf("input now=%s => signing refused with %v (grace verification may still continue)",
		t0.Add(61*time.Minute).Format(time.RFC3339), err)
}

func TestUnknownVersion(t *testing.T) {
	r := NewKeyRing()
	if _, ok := r.Get("missing"); ok {
		t.Fatal("unexpected version")
	}
	if _, err := r.State("missing", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := r.SetActive("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestDuplicateRotationRejected(t *testing.T) {
	t0 := time.Now()
	r := NewKeyRing()
	if _, err := r.Rotate("v1", []byte("a"), t0, time.Hour, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Rotate("v1", []byte("b"), t0, time.Hour, time.Hour); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("want ErrDuplicate, got %v", err)
	}
}
