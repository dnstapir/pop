/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Driving several upstreams at once, the way real ones behave: names appearing
 * and disappearing independently, sometimes the same name in more than one
 * feed.
 */
package rig

import (
	"fmt"
	"math/rand"
	"sort"
)

// Churn applies a reproducible stream of changes across a set of feeds.
//
// Seeded, and it records every operation, because a convergence failure that
// cannot be replayed is nearly useless: the interesting bugs here depend on the
// ORDER adds and removals interleave across sources, and "it failed once" does
// not tell you which order did it.
type Churn struct {
	feeds []*Feed
	pool  []string
	rng   *rand.Rand
	ops   []string
}

// NewChurn drives feeds using a pool of candidate names.
//
// The pool is deliberately smaller than the number of operations, so names
// recur: the same name landing in two feeds, and being dropped from one while
// another still carries it, is the case a single feed can never produce.
func NewChurn(seed int64, poolSize int, feeds ...*Feed) *Churn {
	pool := make([]string, 0, poolSize)
	for i := 0; i < poolSize; i++ {
		pool = append(pool, fmt.Sprintf("churn%02d.example.", i))
	}
	return &Churn{feeds: feeds, pool: pool, rng: rand.New(rand.NewSource(seed))}
}

// Step performs one operation and returns a description of it.
//
// Removal is chosen against what the feed actually holds rather than blindly,
// so the stream is a mix of real additions and real removals instead of mostly
// no-ops once the pool is exhausted.
func (c *Churn) Step() string {
	f := c.feeds[c.rng.Intn(len(c.feeds))]
	name := c.pool[c.rng.Intn(len(c.pool))]
	held := f.Rules()

	var op string
	if _, present := held[name]; present && c.rng.Intn(100) < 45 {
		f.Remove(name)
		op = fmt.Sprintf("remove %s from %s", name, f.Zone())
	} else {
		f.Set(name, NXDOMAIN)
		op = fmt.Sprintf("add %s to %s", name, f.Zone())
	}
	c.ops = append(c.ops, op)
	return op
}

// Expected is the set of names that should be served: the union of what the
// feeds currently hold.
//
// Read from the feeds rather than tracked alongside them. A model maintained in
// parallel can drift from what was actually published, and then the test is
// checking the model against itself.
func (c *Churn) Expected() []string {
	seen := map[string]bool{}
	for _, f := range c.feeds {
		for name := range f.Rules() {
			seen[name] = true
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Ops is everything done so far, for replaying a failure.
func (c *Churn) Ops() []string { return c.ops }
