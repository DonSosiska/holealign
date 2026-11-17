package main

// Registers the "sqlite" database/sql driver that Syft needs to read newer RPM databases.
//
// The driver is registered here and not in internal/agent/inventory on purpose: the server binary
// links inventory (built-in local agent) and already links github.com/glebarez/go-sqlite through
// Grype and the store; both register the driver name "sqlite", so a second registration would
// panic at start. The agent binary has no other SQLite driver.
import _ "modernc.org/sqlite"
