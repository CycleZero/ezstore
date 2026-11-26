package gormstore

// prefixRange turns a prefix into a half-open key range [lo, hi). This is
// exact and index friendly on both SQLite and MySQL, unlike LIKE, whose
// wildcard escaping differs between the two.
//
// Secret names are restricted to ASCII, so incrementing the final byte cannot
// produce invalid UTF-8.
func prefixRange(prefix string) (lo, hi string) {
	b := []byte(prefix)
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] < 0xFF {
			b[i]++
			return prefix, string(b[:i+1])
		}
	}
	// Every byte was 0xFF; fall back to an unbounded upper edge.
	return prefix, prefix + "\uFFFD"
}
