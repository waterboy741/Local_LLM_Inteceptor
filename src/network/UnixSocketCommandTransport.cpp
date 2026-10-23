#include "UnixSocketCommandTransport.hpp"

#include "UnixPeerCredentials.hpp"

#include <QElapsedTimer>
#include <array>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <limits>
#include <poll.h>
#include <sys/socket.h>

namespace interceptor {
namespace {
constexpr int requestTimeoutMs = 1000;
constexpr quint32 maximumFrameSize = 256;
constexpr quint8 protocolVersion = 1;

bool isUnixStreamSocket(int fd) {
    int socketType = 0;
    socklen_t socketTypeSize = sizeof(socketType);
    return ::getsockopt(fd, SOL_SOCKET, SO_TYPE, &socketType, &socketTypeSize) == 0 &&
           socketTypeSize == sizeof(socketType) && socketType == SOCK_STREAM;
}

bool waitFor(int fd, short events, QElapsedTimer &timer, QString *error) {
    for (;;) {
        const qint64 remaining = requestTimeoutMs - timer.elapsed();
        if (remaining <= 0) {
            if (error)
                *error = QStringLiteral("request_timeout");
            return false;
        }

        pollfd descriptor{fd, events, 0};
        const int result = ::poll(&descriptor, 1, static_cast<int>(remaining));
        if (result < 0 && errno == EINTR)
            continue;
        if (result == 0) {
            if (error)
                *error = QStringLiteral("request_timeout");
            return false;
        }
        if (result < 0 || (descriptor.revents & (POLLERR | POLLNVAL)) != 0 ||
            ((descriptor.revents & POLLHUP) != 0 && events != POLLIN)) {
            if (error)
                *error = QStringLiteral("socket_io_error");
            return false;
        }
        if ((descriptor.revents & events) != 0 ||
            (events == POLLIN && (descriptor.revents & POLLHUP) != 0))
            return true;
    }
}

bool readExact(int fd, char *destination, qsizetype size, QElapsedTimer &timer, QString *error) {
    qsizetype offset = 0;
    while (offset < size) {
        if (!waitFor(fd, POLLIN, timer, error))
            return false;
        const ssize_t count =
            ::recv(fd, destination + offset, static_cast<size_t>(size - offset), MSG_DONTWAIT);
        if (count > 0) {
            offset += static_cast<qsizetype>(count);
            continue;
        }
        if (count == 0) {
            if (error)
                *error = QStringLiteral("incomplete_request");
            return false;
        }
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            continue;
        if (error)
            *error = QStringLiteral("socket_read_failed");
        return false;
    }
    return true;
}

bool writeResponse(int fd, quint8 response, QElapsedTimer &timer, QString *error) {
#if defined(SO_NOSIGPIPE)
    const int enabled = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) {
        if (error)
            *error = QStringLiteral("socket_response_setup_failed");
        return false;
    }
#endif
    for (;;) {
        if (!waitFor(fd, POLLOUT, timer, error))
            return false;
#if defined(MSG_NOSIGNAL)
        const ssize_t count = ::send(fd, &response, sizeof(response), MSG_DONTWAIT | MSG_NOSIGNAL);
#else
        const ssize_t count = ::send(fd, &response, sizeof(response), MSG_DONTWAIT);
#endif
        if (count == 1)
            return true;
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        if (error)
            *error = QStringLiteral("socket_response_failed");
        return false;
    }
}

bool requestEndedWithoutTrailingBytes(int fd, QElapsedTimer &timer, QString *error) {
    for (;;) {
        if (!waitFor(fd, POLLIN, timer, error))
            return false;
        char extra = 0;
        const ssize_t count = ::recv(fd, &extra, sizeof(extra), MSG_PEEK | MSG_DONTWAIT);
        if (count == 0)
            return true;
        if (count > 0) {
            if (error)
                *error = QStringLiteral("multiple_or_trailing_requests");
            return false;
        }
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            continue;
        if (error)
            *error = QStringLiteral("socket_read_failed");
        return false;
    }
}

bool validAnchor(const QByteArray &bytes, QString *anchor) {
    const QString decoded = QString::fromUtf8(bytes.constData(), bytes.size());
    if (decoded.toUtf8() != bytes || !decoded.startsWith(QStringLiteral("llm_interceptor/")))
        return false;
    const QString sessionId = decoded.mid(QStringLiteral("llm_interceptor/").size());
    if (sessionId.isEmpty() || sessionId.size() > 48)
        return false;
    for (const QChar character : sessionId) {
        if (!character.isLetterOrNumber() || character.unicode() > 0x7f) {
            if (character != QLatin1Char('_') && character != QLatin1Char('-'))
                return false;
        }
    }
    *anchor = decoded;
    return true;
}

bool decodeCommand(const QByteArray &frame, HelperCommand *command, QString *error) {
    auto reject = [error](const QString &reason) {
        if (error)
            *error = reason;
        return false;
    };
    if (frame.size() < 1 + 1 + 1 + 32 + 1 + 1 ||
        static_cast<quint8>(frame.at(0)) != protocolVersion)
        return reject(QStringLiteral("unsupported_or_incomplete_request"));

    const quint8 rawType = static_cast<quint8>(frame.at(1));
    HelperCommand::Type type;
    switch (rawType) {
    case 1:
        type = HelperCommand::Type::Heartbeat;
        break;
    case 2:
        type = HelperCommand::Type::Stop;
        break;
    default:
        return reject(QStringLiteral("command_not_allowlisted"));
    }

    qsizetype offset = 2;
    const quint8 capabilityLength = static_cast<quint8>(frame.at(offset++));
    if (capabilityLength < 32 || capabilityLength > 128 ||
        frame.size() < offset + capabilityLength + 1)
        return reject(QStringLiteral("invalid_capability_length"));
    const QByteArray capability = frame.mid(offset, capabilityLength);
    offset += capabilityLength;

    const quint8 anchorLength = static_cast<quint8>(frame.at(offset++));
    if (anchorLength == 0 || anchorLength > 64 || frame.size() != offset + anchorLength)
        return reject(QStringLiteral("invalid_anchor_length_or_trailing_data"));
    QString anchor;
    if (!validAnchor(frame.mid(offset, anchorLength), &anchor))
        return reject(QStringLiteral("invalid_anchor"));

    command->type = type;
    command->capability = capability;
    command->anchor = anchor;
    return true;
}

bool sendRejected(int fd, QString *error, const QString &reason) {
    if (error)
        *error = reason;
    QString responseError;
    QElapsedTimer responseTimer;
    responseTimer.start();
    writeResponse(fd, 0, responseTimer, &responseError);
    return false;
}
} // namespace

bool dispatchOneUnixSocketCommand(int connectedSocketFd, HelperDispatcher &dispatcher,
                                  QString *error) {
    if (error)
        error->clear();
    const auto peer = verifiedPeerForUnixSocket(connectedSocketFd, error);
    if (!peer)
        return false;
    if (!isUnixStreamSocket(connectedSocketFd)) {
        if (error)
            *error = QStringLiteral("unix_stream_socket_required");
        return false;
    }

    QElapsedTimer timer;
    timer.start();
    std::array<unsigned char, 4> lengthBytes{};
    if (!readExact(connectedSocketFd, reinterpret_cast<char *>(lengthBytes.data()),
                   static_cast<qsizetype>(lengthBytes.size()), timer, error))
        return false;
    const quint32 frameSize = (static_cast<quint32>(lengthBytes[0]) << 24) |
                              (static_cast<quint32>(lengthBytes[1]) << 16) |
                              (static_cast<quint32>(lengthBytes[2]) << 8) |
                              static_cast<quint32>(lengthBytes[3]);
    if (frameSize == 0 || frameSize > maximumFrameSize)
        return sendRejected(connectedSocketFd, error, QStringLiteral("frame_size_out_of_bounds"));

    QByteArray frame(static_cast<qsizetype>(frameSize), Qt::Uninitialized);
    if (!readExact(connectedSocketFd, frame.data(), frame.size(), timer, error))
        return false;
    if (!requestEndedWithoutTrailingBytes(connectedSocketFd, timer, error)) {
        const QString reason =
            error && !error->isEmpty() ? *error : QStringLiteral("multiple_or_trailing_requests");
        return sendRejected(connectedSocketFd, error, reason);
    }

    HelperCommand command;
    QString decodeError;
    if (!decodeCommand(frame, &command, &decodeError))
        return sendRejected(connectedSocketFd, error, decodeError);

    const auto nowMs = dispatcher.trustedMonotonicNowMs();
    if (!nowMs)
        return sendRejected(connectedSocketFd, error, QStringLiteral("trusted_clock_unavailable"));
    command.nowMs = *nowMs;

    const bool accepted = dispatcher.dispatch(*peer, command);
    QElapsedTimer responseTimer;
    responseTimer.start();
    if (!writeResponse(connectedSocketFd, accepted ? 1 : 0, responseTimer, error)) {
        if (error) {
            *error = accepted ? QStringLiteral("command_may_have_applied_response_failed")
                              : QStringLiteral("command_rejected_response_failed");
        }
        return false;
    }
    if (!accepted && error)
        *error = QStringLiteral("command_rejected_by_dispatcher");
    return accepted;
}

} // namespace interceptor
