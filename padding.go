package main

// SPIDER-SEC-3 — optional traffic shaping.
//
// This file is byte-identical in client/padding.go and server/padding.go
// (see the note at the top of crypto.go).
//
// Design rules, in priority order:
//
//  1. Padding is OFF by default. Shipping it on would make every deployment
//     carry an extra signature it did not ask for.
//  2. Neither the size nor the timing is fixed. A constant-size frame on a
//     fixed period is itself a fingerprint and makes the tunnel *easier* to
//     classify, not harder — a perpetual 50KB beacon would be strictly worse
//     than sending nothing.
//  3. Padding never touches application data. It is a record type the
//     receiver decrypts and discards before the frame decoder ever sees it,
//     so it cannot reorder, delay or corrupt a byte of relayed traffic.
//  4. The rate is capped, so padding cannot turn into a bandwidth amplifier.

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sync"
	"time"
)

// PaddingConfig is the traffic-shaping policy. Sizes are candidate frame
// lengths in bytes; Weights is the probability of picking each one.
type PaddingConfig struct {
	Enabled bool      `json:"enabled"`
	Sizes   []int     `json:"sizes"`
	Weights []float64 `json:"weights"`

	// MinInterval / MaxInterval bound a uniformly random wait before each
	// frame. Uniform, not Poisson-with-a-fixed-mean: a distribution with a
	// sharp mode is itself periodic at its mean.
	MinInterval time.Duration `json:"-"`
	MaxInterval time.Duration `json:"-"`

	// MaxKbps caps the padding rate (kibibits/second). 0 means no cap.
	MaxKbps int `json:"max_kbps"`
}

// paddingConfigJSON is the on-disk shape: intervals are duration strings.
//
// It carries two spellings of the same policy. The precise ones — sizes,
// weights, min_interval, max_interval — are what actually run. The simple
// ones — padding_enabled, padding_min_size, padding_max_size,
// padding_interval — are the shorthand an operator reaches for first, and
// they are translated into the precise form at load time so there is exactly
// one thing to validate. When both are present the precise one wins: an
// operator who spelled out sizes meant those sizes.
type paddingConfigJSON struct {
	Enabled        bool      `json:"enabled"`
	PaddingEnabled *bool     `json:"padding_enabled"`
	Sizes          []int     `json:"sizes"`
	Weights        []float64 `json:"weights"`
	MinInterval    string    `json:"min_interval"`
	MaxInterval    string    `json:"max_interval"`
	MaxKbps        int       `json:"max_kbps"`

	PaddingMinSize  int    `json:"padding_min_size"`
	PaddingMaxSize  int    `json:"padding_max_size"`
	PaddingInterval string `json:"padding_interval"`
}

// UnmarshalJSON accepts duration strings for the interval bounds.
func (p *PaddingConfig) UnmarshalJSON(data []byte) error {
	var raw paddingConfigJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	p.Enabled = raw.Enabled
	if raw.PaddingEnabled != nil {
		p.Enabled = *raw.PaddingEnabled
	}
	p.MaxKbps = raw.MaxKbps

	// Sizes: the explicit list wins; otherwise derive one from the range.
	p.Sizes = raw.Sizes
	p.Weights = raw.Weights
	if len(p.Sizes) == 0 && (raw.PaddingMinSize > 0 || raw.PaddingMaxSize > 0) {
		p.Sizes, p.Weights = buildSizeLadder(raw.PaddingMinSize, raw.PaddingMaxSize)
	}

	p.MinInterval = 0
	p.MaxInterval = 0
	switch {
	case raw.MinInterval != "" || raw.MaxInterval != "":
		d, err := time.ParseDuration(raw.MinInterval)
		if err != nil {
			return fmt.Errorf("padding.min_interval: %w", err)
		}
		p.MinInterval = d
		d, err = time.ParseDuration(raw.MaxInterval)
		if err != nil {
			return fmt.Errorf("padding.max_interval: %w", err)
		}
		p.MaxInterval = d
	case raw.PaddingInterval != "":
		d, err := time.ParseDuration(raw.PaddingInterval)
		if err != nil {
			return fmt.Errorf("padding.padding_interval: %w", err)
		}
		p.MinInterval, p.MaxInterval = jitterWindow(d)
	}
	return nil
}

// MarshalJSON renders intervals as duration strings.
func (p PaddingConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(paddingConfigJSON{
		Enabled:     p.Enabled,
		Sizes:       p.Sizes,
		Weights:     p.Weights,
		MinInterval: p.MinInterval.String(),
		MaxInterval: p.MaxInterval.String(),
		MaxKbps:     p.MaxKbps,
	})
}

// DefaultPaddingConfig returns the shipped policy: disabled, with the three
// candidate sizes and a wide, low-rate timing window for operators who opt in.
func DefaultPaddingConfig() PaddingConfig {
	// The ladder is built from the same helper an operator's min/max pair
	// goes through, so the shipped default and a hand-written range can never
	// disagree about what "4KB to 50KB" means. For that range the doubling
	// walk yields 4, 8, 16, 32 KB and then the exact 50 KB upper bound.
	sizes, weights := buildSizeLadder(defaultPaddingMinSize, defaultPaddingMaxSize)
	return PaddingConfig{
		Enabled:     false,
		Sizes:       sizes,
		Weights:     weights,
		MinInterval: 2 * time.Second,
		MaxInterval: 45 * time.Second,
		MaxKbps:     64,
	}
}

// Shipped size range: 4KB through 50KB, in powers of two with the exact upper
// bound appended. See buildSizeLadder for why the walk looks like that.
const (
	defaultPaddingMinSize = 4096
	defaultPaddingMaxSize = 50 * 1024
)

// buildSizeLadder derives a bucket list spanning [minSize, maxSize] together
// with weights that fall off toward the larger buckets.
//
// Doubling from the minimum puts the buckets on values an operator recognises
// (4, 8, 16, 32 KB for the shipped range) instead of an arbitrary spread, and
// the maximum is appended so the range really does reach its stated top. The
// weights favour smaller frames because a padding policy that mostly sends
// small ones shapes the observable distribution while leaving the rate budget
// — which a single 50 KB frame would spend all at once — in reserve.
func buildSizeLadder(minSize, maxSize int) ([]int, []float64) {
	if minSize <= 0 {
		minSize = defaultPaddingMinSize
	}
	if maxSize <= 0 {
		maxSize = minSize
	}
	if minSize > maxSize {
		minSize, maxSize = maxSize, minSize
	}

	sizes := []int{minSize}
	for s := minSize; s < maxSize; {
		if s > math.MaxInt/2 {
			break
		}
		next := s * 2
		if next >= maxSize {
			break
		}
		sizes = append(sizes, next)
		s = next
	}
	if sizes[len(sizes)-1] != maxSize {
		sizes = append(sizes, maxSize)
	}

	return sizes, sizeWeights(len(sizes))
}

// sizeWeights returns n weights that fall off toward the larger buckets,
// normalised to 1.0. It is used both by the ladder above and when an operator
// supplies sizes without weights — otherwise the new size list would be
// validated against the old list's weights and fail on a length mismatch the
// operator never intended to create.
func sizeWeights(n int) []float64 {
	if n <= 0 {
		return nil
	}
	weights := make([]float64, n)
	sum := 0.0
	for i := 0; i < n; i++ {
		weights[i] = 1 / float64(i+1) // 1, 1/2, 1/3, ...
		sum += weights[i]
	}
	for i := range weights {
		weights[i] /= sum
	}
	return weights
}

// jitterWindow turns a single nominal interval into the uniform draw window
// around it: [interval/2, interval*2].
//
// A single value would mean a fixed period, and a fixed period is exactly the
// signature padding exists to avoid. The window is deliberately wide and has
// no mode, so there is nothing for a classifier to lock onto.
func jitterWindow(interval time.Duration) (time.Duration, time.Duration) {
	if interval <= 0 {
		return 0, 0
	}
	// Overflow guard: doubling a duration that already fills the type.
	if interval > time.Duration(math.MaxInt64)/2 {
		return interval / 2, time.Duration(math.MaxInt64)
	}
	return interval / 2, interval * 2
}

// Validate rejects any policy that would produce a predictable pattern.
// An invalid padding config is a fatal configuration error, never a silent
// fallback to "send fixed frames anyway".
func (p *PaddingConfig) Validate() error {
	if len(p.Sizes) == 0 {
		return fmt.Errorf("padding.sizes must not be empty")
	}
	if len(p.Weights) != len(p.Sizes) {
		return fmt.Errorf("padding.weights has %d entries but padding.sizes has %d", len(p.Weights), len(p.Sizes))
	}
	sum := 0.0
	for i, size := range p.Sizes {
		if size <= 0 {
			return fmt.Errorf("padding.sizes[%d] = %d must be positive", i, size)
		}
		if i > 0 && size <= p.Sizes[i-1] {
			return fmt.Errorf("padding.sizes must be strictly increasing (entry %d is %d after %d)", i, size, p.Sizes[i-1])
		}
		if size > MaxPayloadSize {
			return fmt.Errorf("padding.sizes[%d] = %d exceeds the %d byte record limit", i, size, MaxPayloadSize)
		}
		w := p.Weights[i]
		if w <= 0 {
			return fmt.Errorf("padding.weights[%d] = %g must be positive", i, w)
		}
		sum += w
	}
	if math.Abs(sum-1.0) > 0.01 {
		return fmt.Errorf("padding.weights must sum to 1.0, got %g", sum)
	}
	if p.MinInterval <= 0 {
		return fmt.Errorf("padding.min_interval must be positive, got %s", p.MinInterval)
	}
	if p.MaxInterval <= p.MinInterval {
		return fmt.Errorf("padding.max_interval (%s) must be greater than padding.min_interval (%s)", p.MaxInterval, p.MinInterval)
	}
	if p.MaxKbps < 0 {
		return fmt.Errorf("padding.max_kbps must be >= 0 (0 disables the cap), got %d", p.MaxKbps)
	}
	return nil
}

// pickSize draws one candidate length using the configured weights.
// It reads from rnd so tests can make the draw deterministic.
func (p *PaddingConfig) pickSize(rnd io.Reader) (int, error) {
	var raw [8]byte
	if _, err := io.ReadFull(rnd, raw[:]); err != nil {
		return 0, fmt.Errorf("%w: padding size draw: %v", errSec3, err)
	}
	// Uniform in [0,1) from 53 usable random bits.
	u := float64(binary.BigEndian.Uint64(raw[:])>>11) / (1 << 53)
	cum := 0.0
	for i, w := range p.Weights {
		cum += w
		if u < cum || i == len(p.Weights)-1 {
			return p.Sizes[i], nil
		}
	}
	return p.Sizes[len(p.Sizes)-1], nil
}

// nextDelay draws a uniformly random wait in [MinInterval, MaxInterval].
// Uniform across the whole range: no mode, no period, no beacon.
func (p *PaddingConfig) nextDelay(rnd io.Reader) (time.Duration, error) {
	var raw [8]byte
	if _, err := io.ReadFull(rnd, raw[:]); err != nil {
		return 0, fmt.Errorf("%w: padding delay draw: %v", errSec3, err)
	}
	span := int64(p.MaxInterval - p.MinInterval)
	if span <= 0 {
		return p.MinInterval, nil
	}
	// Rejection-free modulo bias is irrelevant at this scale (2^64 vs a span
	// of at most ~2^63 nanoseconds), but keep the draw full-width anyway.
	off := int64(binary.BigEndian.Uint64(raw[:]) % uint64(span))
	return p.MinInterval + time.Duration(off), nil
}

// paddingPacer enforces the rate cap as a token bucket. When a frame does not
// fit the bucket it is dropped rather than queued, because queuing would turn
// a smooth policy into a burst — exactly the signature padding exists to
// avoid.
type paddingPacer struct {
	mu             sync.Mutex
	bytesPerSecond float64
	budget         float64
	last           time.Time
}

func newPaddingPacer(maxKbps int) *paddingPacer {
	bps := float64(maxKbps) * 1024 / 8
	return &paddingPacer{
		bytesPerSecond: bps,
		// Seed one second so the cap applies from the first frame rather
		// than after a dead interval; allow() still caps the bucket at two
		// seconds, so a long idle period cannot become one huge burst.
		budget: bps,
	}
}

// allow reports whether n bytes may be sent now, and debits the bucket.
func (p *paddingPacer) allow(now time.Time, n int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.bytesPerSecond <= 0 {
		return true // cap disabled
	}
	if p.last.IsZero() {
		p.last = now
	}
	if elapsed := now.Sub(p.last).Seconds(); elapsed > 0 {
		p.budget += elapsed * p.bytesPerSecond
		// Cap the burst to two seconds so a long idle period cannot be
		// spent as one enormous frame.
		if max := p.bytesPerSecond * 2; p.budget > max {
			p.budget = max
		}
		p.last = now
	}
	if float64(n) > p.budget {
		return false
	}
	p.budget -= float64(n)
	return true
}

// runPadding pumps PADDING records until ctx is cancelled or send fails.
//
// send takes the raw payload; the caller seals it as a recPadding record.
// onSent is a diagnostic hook (nil is fine).
func runPadding(ctx context.Context, cfg *PaddingConfig, send func(payload []byte) error, onSent func(size int)) {
	if cfg == nil || !cfg.Enabled {
		return
	}
	pacer := newPaddingPacer(cfg.MaxKbps)
	for {
		delay, err := cfg.nextDelay(rand.Reader)
		if err != nil {
			return
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		size, err := cfg.pickSize(rand.Reader)
		if err != nil {
			return
		}
		// Over the rate cap: skip this frame entirely. Do not accumulate it.
		if !pacer.allow(time.Now(), size) {
			continue
		}
		buf := make([]byte, size)
		if _, err := rand.Read(buf); err != nil {
			return
		}
		if err := send(buf); err != nil {
			return
		}
		if onSent != nil {
			onSent(size)
		}
	}
}
