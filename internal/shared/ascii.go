package shared

// StatusClientClosedRequest is the status for a request whose client went
// away before the server finished it (nginx's 499, which Google's API mapping
// uses for a cancelled operation). net/http has no constant for it. It is a
// 4xx, so a trace span stays unset, and unlike 401 it does not claim the
// caller lacked credentials.
const StatusClientClosedRequest = 499

// PrintableASCII reports whether s is at most maxLen bytes, every one of them
// printable ASCII (0x20-0x7E): no control bytes, no CR/LF, nothing a log line
// or span attribute could be forged with. Callers that read an
// attacker-chosen header value own their own maxLen.
func PrintableASCII(s string, maxLen int) bool {
	if len(s) > maxLen {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7E {
			return false
		}
	}
	return true
}
