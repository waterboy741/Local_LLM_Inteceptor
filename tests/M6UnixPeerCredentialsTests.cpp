#include "network/UnixPeerCredentials.hpp"

#include <QtTest>

#include <sys/socket.h>
#include <unistd.h>

using namespace interceptor;

class M6UnixPeerCredentialsTests : public QObject {
    Q_OBJECT

  private slots:
    void connectedUnixSocketReturnsKernelPeerIdentity() {
        int sockets[2] = {-1, -1};
        QCOMPARE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), 0);

        QString error;
        const auto peer = verifiedPeerForUnixSocket(sockets[0], &error);

        QVERIFY2(peer.has_value(), qPrintable(error));
        QVERIFY(peer->transportAuthenticated);
        QCOMPARE(peer->uid, static_cast<quint32>(::getuid()));
        const QByteArray expectedIdentity = QByteArrayLiteral("unix-uid-gid-v1:") +
                                            QByteArray::number(::getuid()) +
                                            QByteArrayLiteral(":") + QByteArray::number(::getgid());
        QCOMPARE(peer->auditIdentity, expectedIdentity);
        QVERIFY(error.isEmpty());

        ::close(sockets[0]);
        ::close(sockets[1]);
    }

    void invalidDescriptorFailsClosed() {
        QString error;
        const auto peer = verifiedPeerForUnixSocket(-1, &error);

        QVERIFY(!peer.has_value());
        QVERIFY(!error.isEmpty());
    }

    void nonSocketDescriptorFailsClosed() {
        int pipeFds[2] = {-1, -1};
        QCOMPARE(::pipe(pipeFds), 0);

        QString error;
        const auto peer = verifiedPeerForUnixSocket(pipeFds[0], &error);

        QVERIFY(!peer.has_value());
        QVERIFY(!error.isEmpty());
        ::close(pipeFds[0]);
        ::close(pipeFds[1]);
    }

    void unconnectedUnixSocketFailsClosed() {
        const int socketFd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        QVERIFY(socketFd >= 0);

        QString error;
        const auto peer = verifiedPeerForUnixSocket(socketFd, &error);

        QVERIFY(!peer.has_value());
        QCOMPARE(error, QStringLiteral("peer_credentials_require_connected_unix_socket"));
        ::close(socketFd);
    }
};

QTEST_GUILESS_MAIN(M6UnixPeerCredentialsTests)
#include "M6UnixPeerCredentialsTests.moc"
