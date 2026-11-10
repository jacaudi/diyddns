package shared

// CapabilityRotation is the check-in capability a client advertises in the
// "capabilities" array of POST /agent/v1/checkin to say it can perform secret
// and certificate rotation (#175). It is a wire contract between server and
// client: never rename or reuse it. A client sends it only when
// GET /agent/v1/capabilities reports "rotation": true, because the server
// rejects unknown body fields.
const CapabilityRotation = "rotation"
