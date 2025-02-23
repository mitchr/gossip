package server

import "testing"

func BenchmarkWhowasStackSearch(b *testing.B) {
	w := whowasStack{}
	w.push("n", "u", "h", "r")
	nicks := []string{"n"}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for range w.search(nicks, 1) {
		}
	}
}
