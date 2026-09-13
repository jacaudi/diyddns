package feed_test

// No new test lives in this file. Design §10 test 7 asks for a dedicated test
// pinning "a WebSocket upgrade survives the full chain" -- but that coverage
// already exists, and duplicating it would be redundant, not additive (task-
// 12-brief.md's own carve-out: "if chain() and dialStream() already cover
// this, say so ... and add only the missing assertion rather than a duplicate
// test"). This file is the signpost that carve-out call requires, made
// checkable rather than asserted. See also chain()'s doc comment
// (stream_test.go:55), which points back here.
//
// THE MECHANISM. statusRecorder (middleware.go:105-109) embeds only the
// http.ResponseWriter INTERFACE, not a concrete hijackable value:
//
//	type statusRecorder struct {
//		http.ResponseWriter
//		status int
//		bytes  int
//	}
//
// -- so a statusRecorder never satisfies http.Hijacker itself, at ANY nesting
// depth; the only path to a Hijacker is Unwrap()-ing down to the concrete
// writer underneath. That already makes Unwrap load-bearing with a single
// wrapping layer (TestAccessLog_ResponseWriterUnwrapsToHijacker,
// middleware_test.go:276, proves exactly this through a chain with only
// AccessLog's wrap). What THIS invariant adds is that the production chain
// nests TWO such wrappers, not one: Trace (middleware.go:299-361) sits
// OUTSIDE AccessLog (server.go:341-374, RequestID -> Trace -> AccessLog ->
// Recover -> mux), and both wrap the ResponseWriter they are handed in their
// own statusRecorder, so a real request's Hijack call must walk Unwrap
// through both layers, not just one, to reach the real connection.
//
// THE EXISTING COVERAGE. chain(t, logBuf) (stream_test.go:64) builds
// server.Handler(cfg, st, log, server.NopInstruments{}) -- the real,
// unconditional handler() chain, so it carries BOTH wrapping layers: Trace
// constructs its statusRecorder regardless of whether the tracer it is
// handed is real or a no-op (middleware.go:313-317), so NopInstruments does
// not remove the double wrap this invariant is about. dial(t, srv, opts)
// (stream_test.go:113) then drives a real websocket.Dial through that chain
// and calls t.Fatalf on any non-101 response, naming the exact failure mode
// in its own message ("a 501 here means AccessLog's recorder lost Unwrap").
// Every chain(t, ...)-based test in this package calls dial() and so
// exercises this on every run.
//
// THE PROOF, reproducible in one command against the WHOLE tree -- not just
// this package, which is exactly the scope that let Task 8's critic mis-rule
// this invariant "owned by Task 12" without a test existing yet:
//
//	$ GOTOOLCHAIN=go1.27.1 go test ./internal/... 2>&1 | grep -E '^--- FAIL'
//	--- FAIL: TestStream_ThroughRealChain_SnapshotFirstAndEqualToJSONRoute (0.01s)
//	--- FAIL: TestStream_DeltasArriveInBumpOrder_AfterSnapshot (0.01s)
//	--- FAIL: TestStream_ClientDataFrameUnderLimitIsIgnored_OverLimitCloses1009 (0.01s)
//	--- FAIL: TestStream_StalledClientIsCutWith1013_ServerSide (0.01s)
//	--- FAIL: TestStream_ConnectionCapAnswers503 (0.01s)
//	--- FAIL: TestStream_RevokeCloses4001 (0.01s)
//	--- FAIL: TestStream_ShutdownCloses1001WithinBudget (0.01s)
//	--- FAIL: TestStream_ShutdownTimesOutThenPumpsStillExit (0.01s)
//	--- FAIL: TestStream_PeerThatStopsAnsweringPingsIsClosed1001 (0.01s)
//	--- FAIL: TestAccessLog_ResponseWriterUnwrapsToHijacker (0.00s)
//
// -- produced by deleting statusRecorder.Unwrap (middleware.go:131) and
// restored by putting it back, with no other change. The nine TestStream_*
// failures are every chain(t, ...)-based test in THIS package -- every one
// that dials through the real production chain. The tenth,
// TestAccessLog_ResponseWriterUnwrapsToHijacker in internal/server/middleware,
// is Task 8's own single-layer guard (proven above to be a real, narrower
// guard, not a substitute for this one): both stay in the suite.
// dialStream (stream_basic_test.go:20) is the OTHER harness in this package:
// it drives a bare http.NewServeMux() + feed.Register(...) directly, with no
// server.Handler and no Trace/AccessLog, so it does NOT exercise this
// invariant -- it tests the feed handlers in isolation, on purpose, and is
// unaffected by this mutation.
