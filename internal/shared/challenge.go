package shared

// HeaderWWWAuthenticate carries the challenge every 401 must send (RFC 9110
// §15.5.2).
const HeaderWWWAuthenticate = "WWW-Authenticate"

// The challenges, one per kind of credential. None is Basic, Digest, NTLM or
// Negotiate, the only schemes a browser answers with its own credentials
// prompt, so a 401 on a web UI API call never pops one up.
const (
	// ChallengeBearer is for a credential sent as Authorization: Bearer: a
	// feed token or an API key.
	ChallengeBearer = `Bearer realm="diyddns"` // #nosec G101 -- an authentication scheme name, not a credential value; gosec's keyword heuristic fires on "Bearer" in the identifier name
	// ChallengeHMAC is for the agent routes' signed-request headers.
	ChallengeHMAC = `DIYDDNS-HMAC realm="diyddns"`
	// ChallengeDIYDDNS is for a credential no HTTP authentication scheme
	// covers: the session cookie, or one that rides in the request body (a
	// bootstrap token, a registration link, a passkey assertion, an
	// enrollment code).
	ChallengeDIYDDNS = `DIYDDNS realm="diyddns"`
)
