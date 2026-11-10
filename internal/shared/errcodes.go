package shared

// Stable error codes carried in the `code` field of problem JSON bodies on the
// agent-mTLS paths (#173). They are a wire contract between server and client:
// never rename or reuse one.
const (
	// CodeClientCertRejected (401): the agent port refused the client
	// certificate. Authenticated, so the client re-provisions rather than
	// treating it as a rejected HMAC credential.
	CodeClientCertRejected = "client_cert_rejected"
	// CodeCertAlreadyIssued (409): the main port will not issue a second
	// certificate while the device has a live one.
	CodeCertAlreadyIssued = "cert_already_issued"
	// CodeMTLSRequired (403): the main port refuses check-in and self when
	// agent.require_mtls is set.
	CodeMTLSRequired = "mtls_required"
	// CodeNoSecretRotationPending (409): the device has no secret rotation
	// requested; the client drops its pending secret.
	CodeNoSecretRotationPending = "no_secret_rotation_pending"
)
