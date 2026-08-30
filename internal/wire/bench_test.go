package wire

import (
	"os"
	"testing"
)

// Parsing is the only code in this repository that runs on bytes an attacker
// chose, once per packet, before anything else has had a chance to reject them.
// The inputs here are the captured messages in testdata rather than hand-built
// ones, so the numbers describe real messages with real compression pointers in
// them.

func benchMessage(b *testing.B, name string) []byte {
	b.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		b.Fatalf("reading %s: %v", name, err)
	}
	return raw
}

func BenchmarkUnpackAnswer(b *testing.B) {
	raw := benchMessage(b, "example-com-a.bin")
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := Unpack(raw); err != nil {
			b.Fatalf("Unpack: %v", err)
		}
	}
}

// The referral is the message the resolver spends most of its time on during a
// cold walk, and it is the larger of the two: thirteen NS records with glue,
// every name compressed against the ones before it.
func BenchmarkUnpackReferral(b *testing.B) {
	raw := benchMessage(b, "com-ns-referral.bin")
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := Unpack(raw); err != nil {
			b.Fatalf("Unpack: %v", err)
		}
	}
}

func BenchmarkPackReferral(b *testing.B) {
	raw := benchMessage(b, "com-ns-referral.bin")
	msg, err := Unpack(raw)
	if err != nil {
		b.Fatalf("Unpack: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := msg.Pack(); err != nil {
			b.Fatalf("Pack: %v", err)
		}
	}
}

// Name parsing is called on every question and every record, and it is where
// the escape handling lives, so it is worth its own number.
func BenchmarkParseName(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		if _, err := ParseName("www.example.com"); err != nil {
			b.Fatalf("ParseName: %v", err)
		}
	}
}
