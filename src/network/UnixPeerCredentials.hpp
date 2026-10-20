#pragma once

#include "HelperDispatcher.hpp"

#include <optional>

namespace interceptor {

// Derive UID/GID credentials from a connected Unix-domain socket using the operating system.
// This does not identify the connecting executable or verify its code signature; a privileged
// service must apply its own executable/signing policy before trusting a peer. Request payloads
// must never be used to construct a VerifiedPeer.
std::optional<VerifiedPeer> verifiedPeerForUnixSocket(int connectedSocketFd,
                                                      QString *error = nullptr);

} // namespace interceptor
