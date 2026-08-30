package cache

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/DevInIndia/hollow/internal/wire"
)

// The cache sits on the path of every query, so what matters is not that a
// lookup is fast in isolation but that it stays fast with every worker in the
// pool hitting it at once. Both benchmarks below run parallel for that reason:
// the sequential number would hide the thing the sharding exists to prevent.

func benchQuestions(n int) []wire.Question {
	qs := make([]wire.Question, n)
	for i := range qs {
		qs[i] = wire.Question{
			Name:  wire.Name(fmt.Sprintf("host%d.example.com.", i)),
			Type:  wire.TypeA,
			Class: wire.ClassIN,
		}
	}
	return qs
}

func benchAnswer(q wire.Question) *wire.Message {
	return &wire.Message{
		Header:    wire.Header{Response: true, Authoritative: true},
		Questions: []wire.Question{q},
		Answers: []wire.RR{{
			Name: q.Name, Type: wire.TypeA, Class: wire.ClassIN, TTL: 3600,
			Data: wire.A{Addr: netip.MustParseAddr("93.184.216.34")},
		}},
	}
}

func BenchmarkAnswerHit(b *testing.B) {
	const names = 4096
	qs := benchQuestions(names)
	c := New(Config{Entries: names * 2})
	for _, q := range qs {
		c.StoreAnswer(q, benchAnswer(q))
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var i int
		for pb.Next() {
			if _, ok := c.Answer(qs[i%names]); !ok {
				b.Fatal("a stored answer was not found")
			}
			i++
		}
	})
}

// A miss is the case a flood of random subdomains produces, so it has to be
// cheap for the same reason the bounded name counters do.
func BenchmarkAnswerMiss(b *testing.B) {
	c := New(Config{Entries: 4096})
	q := wire.Question{Name: "absent.example.com.", Type: wire.TypeA, Class: wire.ClassIN}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, ok := c.Answer(q); ok {
				b.Fatal("a name that was never stored was found")
			}
		}
	})
}

// Storing over the entry cap, so every iteration also evicts. This is the
// steady state of a busy cache rather than the empty one, and it is where the
// LRU list work shows up.
func BenchmarkStoreAnswerWithEviction(b *testing.B) {
	const names = 4096
	qs := benchQuestions(names)
	msgs := make([]*wire.Message, names)
	for i, q := range qs {
		msgs[i] = benchAnswer(q)
	}
	c := New(Config{Entries: names / 4})

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var i int
		for pb.Next() {
			c.StoreAnswer(qs[i%names], msgs[i%names])
			i++
		}
	})
}
