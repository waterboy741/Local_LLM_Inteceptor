#pragma once

#include "HelperDispatcher.hpp"

namespace interceptor {

// Process one authenticated Heartbeat or Stop request from an already accepted, connected
// Unix-domain SOCK_STREAM socket. The function obtains peer credentials from the socket itself
// and obtains time from HelperDispatcher's trusted monotonic clock. The same clock drives the
// optional HelperWatchdog scheduler. Start and Watchdog are unsupported; this transport has no
// safe snapshot/capability bootstrap.
// The client must half-close its write side after the request. The caller retains ownership of the
// fd, must invoke this once per connection, and must close it afterward. If dispatch succeeds but
// the response fails, false is returned with an error that says the command may have applied.
bool dispatchOneUnixSocketCommand(int connectedSocketFd, HelperDispatcher &dispatcher,
                                  QString *error = nullptr);

} // namespace interceptor
