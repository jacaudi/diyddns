package enroll

import "errors"

// Sentinel errors classifying a device-code enrollment outcome. The command
// layer maps each to a distinct operator message and a non-zero exit.
var (
	// ErrDeviceUnsupported: server reports OIDC device flow unavailable (501, start-only).
	ErrDeviceUnsupported = errors.New("enroll: server does not support OIDC device enrollment")
	// ErrFlowGone: the device flow is gone, denied, or expired server-side (410).
	ErrFlowGone = errors.New("enroll: device authorization denied or expired")
	// ErrRejected: the user authenticated but enrollment was not authorized (401).
	ErrRejected = errors.New("enroll: enrollment not authorized")
	// ErrBadGateway: the server could not reach the identity provider (502).
	ErrBadGateway = errors.New("enroll: server could not reach the identity provider")
	// ErrServer: server internal error (500 or other unexpected status).
	ErrServer = errors.New("enroll: server error")
	// ErrExpired: the device code expired before the user authorized.
	ErrExpired = errors.New("enroll: device code expired before authorization")
	// ErrProtocol: the server returned a 200 that does not match the contract.
	ErrProtocol = errors.New("enroll: unexpected server response")
	// ErrEnrollUnauthorized: the server rejected a code or credential
	// enrollment (uniform 401 — never distinguishes an invalid/expired/used
	// code from an unknown email, wrong password, or disabled account).
	ErrEnrollUnauthorized = errors.New("enroll: invalid enrollment code or credentials")
)
