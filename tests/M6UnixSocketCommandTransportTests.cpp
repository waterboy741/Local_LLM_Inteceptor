#include "network/HelperDispatcher.hpp"
#include "network/UnixPeerCredentials.hpp"
#include "network/UnixSocketCommandTransport.hpp"

#include <QElapsedTimer>
#include <QtTest>
#include <atomic>
#include <chrono>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace interceptor;

class TransportFakeOperations final : public SystemOperations {
  public:
    QStringList calls;
    int forwarding = 0;
    int redirects = 1;
    bool leaseHeld = false;

    std::optional<int> readSetting(NetworkSetting setting) override {
        calls << (setting == NetworkSetting::Forwarding ? "read-forwarding" : "read-redirects");
        return setting == NetworkSetting::Forwarding ? forwarding : redirects;
    }
    SettingChange compareAndSetSetting(NetworkSetting setting, int expected, int desired) override {
        calls << "compare-and-set";
        auto &current = setting == NetworkSetting::Forwarding ? forwarding : redirects;
        if (current == desired)
            return SettingChange::Unchanged;
        if (current != expected)
            return SettingChange::Conflict;
        current = desired;
        return SettingChange::Applied;
    }
    std::optional<QString> acquireSessionLease(const SessionSnapshot &) override {
        calls << "acquire-lease";
        if (leaseHeld)
            return {};
        leaseHeld = true;
        return QStringLiteral("test-lease");
    }
    bool releaseSessionLease(const QString &token) override {
        calls << "release-lease";
        if (token != QStringLiteral("test-lease"))
            return false;
        leaseHeld = false;
        return true;
    }
    std::optional<QString> acquirePfReference() override {
        calls << "acquire-pf-reference";
        return QStringLiteral("test-pf-reference");
    }
    bool releasePfReference(const QString &) override {
        calls << "release-pf-reference";
        return true;
    }
    bool installAnchor(const SessionSnapshot &) override {
        calls << "install-anchor";
        return true;
    }
    bool removeAnchor(const SessionSnapshot &) override {
        calls << "remove-anchor";
        return true;
    }
    bool clearOwnedState(const SessionSnapshot &) override {
        calls << "clear-state";
        return true;
    }
    bool beginArp(const SessionSnapshot &) override {
        calls << "begin-arp";
        return true;
    }
    bool endArp(const SessionSnapshot &) override {
        calls << "end-arp";
        return true;
    }
    bool restoreNeighbors(const SessionSnapshot &) override {
        calls << "restore-neighbors";
        return true;
    }
    bool interfaceAvailable(const SessionSnapshot &) override {
        calls << "interface-available";
        return true;
    }
    bool retainRecovery(const SessionSnapshot &, const OwnershipJournal &) override {
        calls << "retain-recovery";
        return true;
    }
};

class M6UnixSocketCommandTransportTests : public QObject {
    Q_OBJECT

  private:
    static SessionSnapshot validSnapshot() {
        SessionConfig config{"synthetic0", "192.0.2.10",      "192.0.2.30",
                             18081,        {"/api/generate"}, false};
        NetworkFacts facts;
        facts.interfaceName = "synthetic0";
        facts.researchIp = "192.0.2.20";
        facts.researchMac = "02:00:00:00:00:20";
        facts.clientMac = "02:00:00:00:00:10";
        facts.serverMac = "02:00:00:00:00:30";
        facts.proxyServerIp = config.serverIp;
        facts.proxyServerPort = config.serverPort;
        facts.proxyListenPort = 11434;
        facts.interfaceUp = facts.sameLink = facts.anchorAttached = facts.proxyReady =
            facts.authorized = true;
        const auto snapshot = SessionSnapshot::create(config, facts, 11434, "transport-test");
        if (!snapshot)
            qFatal("Cannot construct synthetic transport snapshot");
        return *snapshot;
    }
    static QByteArray capability() { return QByteArray(32, 'a'); }
    static VerifiedPeer kernelPeer() {
        int sockets[2] = {-1, -1};
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
            qFatal("Cannot create synthetic Unix socket pair");
        const auto peer = verifiedPeerForUnixSocket(sockets[0]);
        ::close(sockets[0]);
        ::close(sockets[1]);
        if (!peer)
            qFatal("Cannot read synthetic Unix peer credentials");
        return *peer;
    }
    static QByteArray payload(quint8 command, const QByteArray &token, const QByteArray &anchor,
                              const QByteArray &suffix = {}) {
        QByteArray result;
        result.append(char(1));
        result.append(static_cast<char>(command));
        result.append(static_cast<char>(token.size()));
        result.append(token);
        result.append(static_cast<char>(anchor.size()));
        result.append(anchor);
        result.append(suffix);
        return result;
    }
    static QByteArray frame(const QByteArray &payloadBytes) {
        const quint32 length = static_cast<quint32>(payloadBytes.size());
        QByteArray result;
        result.append(static_cast<char>((length >> 24) & 0xff));
        result.append(static_cast<char>((length >> 16) & 0xff));
        result.append(static_cast<char>((length >> 8) & 0xff));
        result.append(static_cast<char>(length & 0xff));
        result.append(payloadBytes);
        return result;
    }
    static void writeAll(int fd, const QByteArray &bytes) {
        qsizetype offset = 0;
        while (offset < bytes.size()) {
            const auto count =
                ::write(fd, bytes.constData() + offset, static_cast<size_t>(bytes.size() - offset));
            if (count <= 0)
                qFatal("Cannot write synthetic transport request");
            offset += static_cast<qsizetype>(count);
        }
    }
    static bool request(HelperDispatcher &dispatcher, const QByteArray &wire, QByteArray *response,
                        QString *error = nullptr) {
        int sockets[2] = {-1, -1};
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
            qFatal("Cannot create transport test socket pair");
        writeAll(sockets[1], wire);
        if (::shutdown(sockets[1], SHUT_WR) != 0)
            qFatal("Cannot half-close transport test socket");
        const bool accepted = dispatchOneUnixSocketCommand(sockets[0], dispatcher, error);
        response->clear();
        char reply = 0;
        if (::recv(sockets[1], &reply, sizeof(reply), MSG_DONTWAIT) == 1)
            response->append(reply);
        ::close(sockets[0]);
        ::close(sockets[1]);
        return accepted;
    }
    static HelperCommand startCommand(const SessionSnapshot &snapshot) {
        HelperCommand command;
        command.type = HelperCommand::Type::Start;
        command.capability = capability();
        command.anchor = snapshot.anchor();
        command.snapshot = snapshot;
        command.nowMs = 100;
        return command;
    }

  private slots:
    void malformedAndSpoofedRequestsDoNotReachOperations() {
        TransportFakeOperations operations;
        const auto snapshot = validSnapshot();
        const auto peer = kernelPeer();
        int clockCalls = 0;
        const auto clock = [&clockCalls] {
            ++clockCalls;
            return qint64(150);
        };
        HelperDispatcher dispatcher(operations, snapshot, peer, capability(), nullptr, clock);
        QVERIFY(dispatcher.dispatch(peer, startCommand(snapshot)));
        const int operationCount = operations.calls.size();
        const auto anchor = snapshot.anchor().toUtf8();

        QByteArray legacyTime = QByteArray::fromHex("0101") + QByteArray(8, '\0');
        legacyTime += static_cast<char>(capability().size());
        legacyTime += capability();
        legacyTime += static_cast<char>(anchor.size());
        legacyTime += anchor;
        QByteArray trailingPeerFields =
            payload(1, capability(), anchor, QByteArrayLiteral("uid=0;authenticated=1"));
        QByteArray extraRequest = frame(payload(1, capability(), anchor));
        extraRequest += QByteArrayLiteral("spoofed-second-frame");

        QList<QPair<QByteArray, bool>> rejected;
        rejected.append({QByteArray::fromHex("0000"), false});
        rejected.append({QByteArray::fromHex("00000000"), true});
        rejected.append({QByteArray::fromHex("00000101"), true});
        rejected.append({frame(QByteArray::fromHex("0101")), true});
        rejected.append({frame(payload(3, capability(), anchor)), true}); // old Watchdog opcode
        rejected.append({frame(payload(0, capability(), anchor)), true}); // Start is unavailable
        rejected.append({frame(payload(1, QByteArray(31, 'a'), anchor)), true});
        rejected.append({frame(payload(1, QByteArray(33, 'a'), anchor)), true});
        rejected.append({frame(payload(1, QByteArray(128, 'a'), anchor)), true});
        rejected.append({frame(payload(1, QByteArray(129, 'a'), anchor)), true});
        rejected.append({frame(payload(1, capability(), QByteArray(65, 'x'))), true});
        rejected.append({frame(payload(1, capability(), anchor, QByteArrayLiteral("x"))), true});
        rejected.append({frame(trailingPeerFields), true});
        rejected.append({frame(legacyTime), true}); // client-supplied timestamp layout
        rejected.append({extraRequest, true});

        for (const auto &[wire, replyExpected] : rejected) {
            QByteArray reply;
            QString error;
            QVERIFY(!request(dispatcher, wire, &reply, &error));
            if (replyExpected)
                QCOMPARE(reply, QByteArray(1, char(0)));
            else
                QVERIFY(reply.isEmpty());
            QVERIFY(!error.isEmpty());
            QCOMPARE(clockCalls, 0);
            QCOMPARE(operations.calls.size(), operationCount);
            QCOMPARE(dispatcher.state(), NetworkSession::State::Active);
        }

        for (const auto &body :
             {payload(1, QByteArray(32, 'b'), anchor),
              payload(1, capability(), QByteArrayLiteral("llm_interceptor/other"))}) {
            QByteArray reply;
            QString error;
            QVERIFY(!request(dispatcher, frame(body), &reply, &error));
            QCOMPARE(reply, QByteArray(1, char(0)));
            QVERIFY(error == QStringLiteral("command_rejected_by_dispatcher"));
            QCOMPARE(clockCalls, 1);
            QCOMPARE(operations.calls.size(), operationCount);
            QCOMPARE(dispatcher.state(), NetworkSession::State::Active);
            clockCalls = 0;
        }

        QByteArray reply;
        QVERIFY(request(dispatcher, frame(payload(1, capability(), anchor)), &reply));
        QCOMPARE(reply, QByteArray(1, char(1)));
        QCOMPARE(clockCalls, 1);
        QCOMPARE(operations.calls.size(), operationCount);
        QCOMPARE(dispatcher.state(), NetworkSession::State::Active);

        QVERIFY(request(dispatcher, frame(payload(2, capability(), anchor)), &reply));
        QCOMPARE(reply, QByteArray(1, char(1)));
        QVERIFY(operations.calls.size() > operationCount);
        QCOMPARE(dispatcher.state(), NetworkSession::State::Idle);
    }

    void noEofAndSlowTrickleTimeOutBeforeDispatch() {
        TransportFakeOperations operations;
        const auto peer = kernelPeer();
        int clockCalls = 0;
        HelperDispatcher dispatcher(operations, validSnapshot(), peer, capability(), nullptr,
                                    [&clockCalls] {
                                        ++clockCalls;
                                        return qint64(200);
                                    });
        int sockets[2] = {-1, -1};
        QCOMPARE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), 0);
#if defined(SO_NOSIGPIPE)
        const int noSignal = 1;
        QCOMPARE(::setsockopt(sockets[1], SOL_SOCKET, SO_NOSIGPIPE, &noSignal, sizeof(noSignal)),
                 0);
#endif
        const QByteArray wire = frame(QByteArray(64, 'x'));
        std::atomic<bool> finished = false;
        std::thread writer([&] {
            for (const char byte : wire) {
                if (finished.load())
                    break;
                if (::write(sockets[1], &byte, 1) != 1)
                    break;
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
        });

        QString error;
        QElapsedTimer elapsed;
        elapsed.start();
        const bool accepted = dispatchOneUnixSocketCommand(sockets[0], dispatcher, &error);
        const qint64 durationMs = elapsed.elapsed();
        finished.store(true);
        writer.join();

        QVERIFY(!accepted);
        QVERIFY2(durationMs >= 800 && durationMs < 1600,
                 qPrintable(QString("Unexpected deadline duration: %1ms").arg(durationMs)));
        QCOMPARE(clockCalls, 0);
        QCOMPARE(error, QStringLiteral("request_timeout"));
        QVERIFY(operations.calls.isEmpty());
        QCOMPARE(dispatcher.state(), NetworkSession::State::Idle);
        ::close(sockets[0]);
        ::close(sockets[1]);
    }

    void completeFrameWithoutClientEofIsRejectedBeforeDispatch() {
        TransportFakeOperations operations;
        const auto peer = kernelPeer();
        int clockCalls = 0;
        HelperDispatcher dispatcher(operations, validSnapshot(), peer, capability(), nullptr,
                                    [&clockCalls] {
                                        ++clockCalls;
                                        return qint64(200);
                                    });
        int sockets[2] = {-1, -1};
        QCOMPARE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), 0);
        const auto anchor = validSnapshot().anchor().toUtf8();
        writeAll(sockets[1], frame(payload(1, capability(), anchor)));

        std::atomic<bool> finished = false;
        std::thread holder([&] {
            std::this_thread::sleep_for(std::chrono::milliseconds(1200));
            if (!finished.load())
                ::shutdown(sockets[1], SHUT_WR);
        });

        QString error;
        QElapsedTimer elapsed;
        elapsed.start();
        const bool accepted = dispatchOneUnixSocketCommand(sockets[0], dispatcher, &error);
        const qint64 durationMs = elapsed.elapsed();
        finished.store(true);
        holder.join();

        QVERIFY(!accepted);
        QVERIFY2(durationMs >= 800 && durationMs < 1600,
                 qPrintable(QString("Unexpected EOF deadline duration: %1ms").arg(durationMs)));
        QCOMPARE(error, QStringLiteral("request_timeout"));
        QCOMPARE(clockCalls, 0);
        QVERIFY(operations.calls.isEmpty());
        QCOMPARE(dispatcher.state(), NetworkSession::State::Idle);
        char reply = 1;
        QCOMPARE(::recv(sockets[1], &reply, sizeof(reply), MSG_DONTWAIT), ssize_t(1));
        QCOMPARE(reply, char(0));
        ::close(sockets[0]);
        ::close(sockets[1]);
    }

    void lostResponseAfterAcceptedStopIsReportedAsPossiblyApplied() {
        TransportFakeOperations operations;
        const auto snapshot = validSnapshot();
        const auto peer = kernelPeer();
        HelperDispatcher dispatcher(operations, snapshot, peer, capability(), nullptr,
                                    [] { return qint64(200); });
        QVERIFY(dispatcher.dispatch(peer, startCommand(snapshot)));
        const int operationCount = operations.calls.size();

        int sockets[2] = {-1, -1};
        QCOMPARE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), 0);
        writeAll(sockets[1], frame(payload(2, capability(), snapshot.anchor().toUtf8())));
        QCOMPARE(::shutdown(sockets[1], SHUT_WR), 0);
        QCOMPARE(::shutdown(sockets[1], SHUT_RD), 0);

        QString error;
        const bool accepted = dispatchOneUnixSocketCommand(sockets[0], dispatcher, &error);

        QVERIFY(!accepted);
        QCOMPARE(error, QStringLiteral("command_may_have_applied_response_failed"));
        QVERIFY(operations.calls.size() > operationCount);
        QCOMPARE(dispatcher.state(), NetworkSession::State::Idle);
        ::close(sockets[0]);
        ::close(sockets[1]);
    }

    void connectedUnixDatagramSocketIsRejectedBeforeReading() {
        TransportFakeOperations operations;
        const auto peer = kernelPeer();
        HelperDispatcher dispatcher(operations, validSnapshot(), peer, capability());
        int sockets[2] = {-1, -1};
        QCOMPARE(::socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets), 0);

        int clockCalls = 0;
        QString error;
        const bool accepted = dispatchOneUnixSocketCommand(sockets[0], dispatcher, &error);

        QVERIFY(!accepted);
        QVERIFY(!error.isEmpty());
        QCOMPARE(clockCalls, 0);
        QVERIFY(operations.calls.isEmpty());
        QCOMPARE(dispatcher.state(), NetworkSession::State::Idle);
        ::close(sockets[0]);
        ::close(sockets[1]);
    }
};

QTEST_GUILESS_MAIN(M6UnixSocketCommandTransportTests)
#include "M6UnixSocketCommandTransportTests.moc"
