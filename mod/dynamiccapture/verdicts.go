package dynamiccapture

import (
	"sync"
	"time"
)

// Verdict tells the capture handler why a request was accepted by the sniff
// handler. Sniff and ingress are correlated via the X-Zoraxy-RequestID header,
// which Zoraxy sets identically on both internal hops.
type Verdict int

const (
	VerdictBlock   Verdict = iota // Banned IP or AppSec in-band match: reply 403
	VerdictInspect                // Request has a body: full AppSec check, then relay
	VerdictCaptcha                // Captcha decision: serve challenge, verify token
)

type verdictEntry struct {
	verdict   Verdict
	expiresAt time.Time
}

// Verdicts is a bounded TTL map of request UUID to sniff verdict.
type Verdicts struct {
	mu      sync.Mutex
	items   map[string]verdictEntry
	ttl     time.Duration
	maxSize int
}

func NewVerdicts() *Verdicts {
	return &Verdicts{
		items:   make(map[string]verdictEntry),
		ttl:     30 * time.Second,
		maxSize: 10000,
	}
}

func (v *Verdicts) Set(uuid string, verdict Verdict) {
	if uuid == "" {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	// Lazy eviction when the map grows beyond its bound.
	if len(v.items) >= v.maxSize {
		now := time.Now()
		for k, e := range v.items {
			if now.After(e.expiresAt) {
				delete(v.items, k)
			}
		}
		if len(v.items) >= v.maxSize {
			v.items = make(map[string]verdictEntry, v.maxSize)
		}
	}
	v.items[uuid] = verdictEntry{verdict: verdict, expiresAt: time.Now().Add(v.ttl)}
}

// Take returns and removes the verdict for uuid. Missing or expired entries
// return ok=false; the caller then falls back to VerdictInspect, the safe
// option (it re-inspects instead of blindly blocking or blindly relaying).
func (v *Verdicts) Take(uuid string) (Verdict, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.items[uuid]
	if !ok || time.Now().After(e.expiresAt) {
		return 0, false
	}
	delete(v.items, uuid)
	return e.verdict, true
}
