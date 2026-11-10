package shared

// DeviceSecretLen is the byte length of a device's HMAC secret: the server
// generates and accepts exactly this many bytes, and the client generates its
// rotation secret at this size.
const DeviceSecretLen = 32
