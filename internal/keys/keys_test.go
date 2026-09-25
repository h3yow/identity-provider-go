package keys

import (
	"errors"
	"log"
	"sync"
	"testing"
)

func TestRotationLifecycle(t *testing.T) {
	r := NewRing()
	k1 := Key{Version: "v1", Secret: []byte("secret-1")}
	k2 := Key{Version: "v2", Secret: []byte("secret-2")}
	k3 := Key{Version: "v3", Secret: []byte("secret-3")}

	if err := r.Add(k1); err != nil {
		t.Fatalf("add v1: %v", err)
	}
	log.Printf("[keys] input=add(v1) => state=%s", r.StateOf("v1"))
	if err := r.Rotate(k2); err != nil {
		t.Fatalf("rotate v2: %v", err)
	}
	if err := r.Rotate(k3); err != nil {
		t.Fatalf("rotate v3: %v", err)
	}

	// 判定依据：轮换后只有最新版本 active，其余进入 verifying。
	cases := []struct {
		v       Version
		want    State
		canSign bool
	}{
		{"v1", StateVerifying, false},
		{"v2", StateVerifying, false},
		{"v3", StateActive, true},
	}
	for _, c := range cases {
		got := r.StateOf(c.v)
		_, state, ok := r.VerifyKey(c.v)
		log.Printf("[keys] input=lookup(%s) => state=%s verify_ok=%t want=%s", c.v, got, ok, c.want)
		if got != c.want {
			t.Errorf("version %s state = %s, want %s", c.v, got, c.want)
		}
		if !ok {
			t.Errorf("version %s should be verifiable during transition", c.v)
		}
		if state != got {
			t.Errorf("version %s VerifyKey state %s != StateOf %s", c.v, state, got)
		}
	}
	if sk, ok := r.SigningKey(); !ok || sk.Version != "v3" {
		t.Fatalf("signing key = %v,%v want v3", sk.Version, ok)
	}
	log.Printf("[keys] basis=signing key is v3; v1/v2 remain in verifying transition window")

	// 过渡期结束：退役 v1，v2 仍可验证 —— 多版本接受窗口可以逐个关闭。
	if err := r.Retire("v1"); err != nil {
		t.Fatalf("retire v1: %v", err)
	}
	if _, state, ok := r.VerifyKey("v1"); ok || state != StateRetired {
		t.Fatalf("retired v1: ok=%v state=%s", ok, state)
	}
	if _, _, ok := r.VerifyKey("v2"); !ok {
		t.Fatalf("v2 must still verify while v1 retired")
	}
	log.Printf("[keys] input=retire(v1) => v1 retired&rejected; basis=v2 still verifying independently")

	// 未知版本与已退役版本必须可区分（VerifyKey 给出不同 state）。
	_, state, ok := r.VerifyKey("ghost")
	log.Printf("[keys] input=lookup(ghost) => ok=%v state=%s basis=never registered => unknown_key", ok, state)
	if ok || state != StateNone {
		t.Fatalf("ghost version: ok=%v state=%s", ok, state)
	}
}

func TestRotationGuards(t *testing.T) {
	r := NewRing()
	if err := r.Add(Key{Version: "v1", Secret: []byte("s")}); err != nil {
		t.Fatal(err)
	}
	log.Printf("[keys] input=add duplicate v1 => expect ErrDuplicateVersion")
	if err := r.Add(Key{Version: "v1", Secret: []byte("other")}); !errors.Is(err, ErrDuplicateVersion) {
		t.Fatalf("duplicate add err = %v", err)
	}
	log.Printf("[keys] input=retire(active v1) => expect ErrActiveCannotRetire")
	if err := r.Retire("v1"); !errors.Is(err, ErrActiveCannotRetire) {
		t.Fatalf("retire active err = %v", err)
	}
	log.Printf("[keys] input=retire(ghost) => expect ErrUnknownVersion")
	if err := r.Retire("ghost"); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("retire unknown err = %v", err)
	}
}

func TestRingConcurrentRotate(t *testing.T) {
	r := NewRing()
	if err := r.Add(Key{Version: "v0", Secret: []byte("s0")}); err != nil {
		t.Fatal(err)
	}
	// 并发轮换不同版本不得产生数据竞争；最终 active 唯一。
	var wg sync.WaitGroup
	for i := 1; i <= 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v := Version("c" + string(rune('a'+i%26)) + itoaTest(i))
			_ = r.Rotate(Key{Version: v, Secret: []byte("secret-" + v)})
		}(i)
	}
	wg.Wait()
	sk, ok := r.SigningKey()
	if !ok {
		t.Fatal("no active after concurrent rotations")
	}
	activeCount := 0
	for _, v := range r.Versions() {
		if r.StateOf(v) == StateActive {
			activeCount++
		}
	}
	log.Printf("[keys] basis=after 20 concurrent rotations: unique_active=%q active_count=%d total=%d",
		sk.Version, activeCount, len(r.Versions()))
	if activeCount != 1 {
		t.Fatalf("active count = %d, want exactly 1", activeCount)
	}
}

func itoaTest(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
