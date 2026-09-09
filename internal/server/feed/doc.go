// Package feed serves the gateway feed (#106): a bearer-token REST snapshot
// of every device currently in the feed (text and JSON), and a WebSocket
// stream of the same membership as it changes. Routes live on the plain
// ServeMux under /feed/v1, absent entirely when feed.enabled is false.
//
// Import direction: feed imports store and nothing else in internal/server;
// service and notify do not import feed. The fan-out that joins the hub to
// the webhook outbox lives in internal/server.
package feed
