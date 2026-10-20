#include "UnixPeerCredentials.hpp"

#include <limits>
#include <sys/socket.h>
#include <sys/types.h>

#if defined(__APPLE__)
#include <unistd.h>
#elif defined(__linux__)
#include <unistd.h>
#endif

namespace interceptor {
namespace {
bool socketIsConnectedUnixDomain(int fd) {
    sockaddr_storage localAddress{};
    socklen_t localLength = sizeof(localAddress);
    if (::getsockname(fd, reinterpret_cast<sockaddr *>(&localAddress), &localLength) != 0 ||
        localAddress.ss_family != AF_UNIX)
        return false;

    sockaddr_storage peerAddress{};
    socklen_t peerLength = sizeof(peerAddress);
    return ::getpeername(fd, reinterpret_cast<sockaddr *>(&peerAddress), &peerLength) == 0 &&
           peerAddress.ss_family == AF_UNIX;
}
} // namespace

std::optional<VerifiedPeer> verifiedPeerForUnixSocket(int connectedSocketFd, QString *error) {
    if (error)
        error->clear();
    if (connectedSocketFd < 0 || !socketIsConnectedUnixDomain(connectedSocketFd)) {
        if (error)
            *error = QStringLiteral("peer_credentials_require_connected_unix_socket");
        return std::nullopt;
    }

    uid_t uid = 0;
    gid_t gid = 0;
#if defined(__APPLE__)
    if (::getpeereid(connectedSocketFd, &uid, &gid) != 0) {
        if (error)
            *error = QStringLiteral("peer_credentials_unavailable");
        return std::nullopt;
    }
#elif defined(__linux__) && defined(SO_PEERCRED)
    struct PeerCredentials {
        pid_t pid;
        uid_t uid;
        gid_t gid;
    } credentials{};
    socklen_t credentialsLength = sizeof(credentials);
    if (::getsockopt(connectedSocketFd, SOL_SOCKET, SO_PEERCRED, &credentials,
                     &credentialsLength) != 0 ||
        credentialsLength != sizeof(credentials)) {
        if (error)
            *error = QStringLiteral("peer_credentials_unavailable");
        return std::nullopt;
    }
    uid = credentials.uid;
    gid = credentials.gid;
#else
    if (error)
        *error = QStringLiteral("peer_credentials_unsupported_platform");
    return std::nullopt;
#endif

    if (static_cast<quint64>(uid) > std::numeric_limits<quint32>::max()) {
        if (error)
            *error = QStringLiteral("peer_uid_out_of_range");
        return std::nullopt;
    }

    VerifiedPeer peer;
    peer.uid = static_cast<quint32>(uid);
    // Preserve both kernel-reported credentials in the dispatcher's identity comparison. This
    // value is a UID/GID credential tuple, not an audit token or code-signing identity.
    peer.auditIdentity = QByteArrayLiteral("unix-uid-gid-v1:") + QByteArray::number(peer.uid) +
                         QByteArrayLiteral(":") + QByteArray::number(static_cast<quint64>(gid));
    peer.transportAuthenticated = true;
    return peer;
}

} // namespace interceptor
