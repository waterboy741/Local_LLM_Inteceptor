#include "network/ArpCodec.hpp"
#include "network/HelperDispatcher.hpp"
#include "network/NetworkSession.hpp"

#include <QFile>
#include <QSet>
#include <QSignalSpy>
#include <QtTest>
#include <type_traits>

using namespace interceptor;
static_assert(!std::is_default_constructible_v<SessionSnapshot>);

// Every mutation below affects only in-memory synthetic state. No OS adapter is
// linked or invoked by this test backend.
class FakeSystemOperations : public SystemOperations {
  public:
    int forwarding = 0;
    int redirects = 1;
    QStringList calls;
    QString failure;
    int failuresRemaining = 1;
    bool partialFailure = true;
    bool available = true;
    bool arpActive = false;
    bool neighborsChanged = false;
    QString activeLease;
    int nextLease = 1;
    bool changeDuringRestore = false;
    bool retainFails = false;
    std::optional<SessionSnapshot> recoverySnapshot;
    std::optional<OwnershipJournal> recoveryJournal;
    QSet<QString> references{"foreign-reference"};
    QSet<QString> anchors{"foreign-anchor"};
    QSet<QString> states{"foreign-state"};

    bool failing(const QString &call) {
        calls.append(call);
        if (failure == call && failuresRemaining > 0) {
            --failuresRemaining;
            return true;
        }
        return false;
    }
    std::optional<int> readSetting(NetworkSetting setting) override {
        const auto name =
            setting == NetworkSetting::Forwarding ? "read-forwarding" : "read-redirects";
        if (failing(name))
            return {};
        return setting == NetworkSetting::Forwarding ? forwarding : redirects;
    }
    SettingChange compareAndSetSetting(NetworkSetting setting, int expected, int desired) override {
        const auto name =
            QString("cas-%1:%2->%3")
                .arg(setting == NetworkSetting::Forwarding ? "forwarding" : "redirects")
                .arg(expected)
                .arg(desired);
        if (failing(name))
            return SettingChange::Failed;
        if (changeDuringRestore && setting == NetworkSetting::Forwarding && desired == 0) {
            forwarding = 2;
            changeDuringRestore = false;
        }
        auto &current = setting == NetworkSetting::Forwarding ? forwarding : redirects;
        if (current == desired)
            return SettingChange::Unchanged;
        if (current != expected)
            return SettingChange::Conflict;
        current = desired;
        return SettingChange::Applied;
    }
    std::optional<QString> acquireSessionLease(const SessionSnapshot &) override {
        if (failing("acquire-lease") || !activeLease.isEmpty())
            return {};
        activeLease = QString("owned-lease-%1").arg(nextLease++);
        return activeLease;
    }
    bool releaseSessionLease(const QString &token) override {
        if (failing("release-lease"))
            return false;
        if (token != activeLease)
            return false;
        activeLease.clear();
        return true;
    }
    std::optional<QString> acquirePfReference() override {
        if (failing("acquire-reference"))
            return {};
        references.insert("owned-reference");
        return QString("owned-reference");
    }
    bool releasePfReference(const QString &token) override {
        const bool failed = failing("release:" + token);
        if (!failed || partialFailure)
            references.remove(token);
        return !failed;
    }
    bool installAnchor(const SessionSnapshot &snapshot) override {
        const bool failed = failing("install-anchor");
        if (!failed || partialFailure) {
            anchors.insert(snapshot.anchor());
            states.insert(snapshot.anchor());
        }
        return !failed;
    }
    bool removeAnchor(const SessionSnapshot &snapshot) override {
        const bool failed = failing("remove-anchor");
        if (!failed || partialFailure)
            anchors.remove(snapshot.anchor());
        return !failed;
    }
    bool clearOwnedState(const SessionSnapshot &snapshot) override {
        const bool failed = failing("clear-owned-state");
        if (!failed || partialFailure)
            states.remove(snapshot.anchor());
        return !failed;
    }
    bool beginArp(const SessionSnapshot &) override {
        const bool failed = failing("begin-arp");
        if (!failed || partialFailure) {
            arpActive = true;
            neighborsChanged = true;
        }
        return !failed;
    }
    bool endArp(const SessionSnapshot &) override {
        const bool failed = failing("end-arp");
        if (!failed || partialFailure)
            arpActive = false;
        return !failed;
    }
    bool restoreNeighbors(const SessionSnapshot &) override {
        const bool failed = failing("restore-neighbors");
        if (!failed || partialFailure)
            neighborsChanged = false;
        return !failed;
    }
    bool interfaceAvailable(const SessionSnapshot &) override {
        return !failing("interface-available") && available;
    }
    bool retainRecovery(const SessionSnapshot &snapshot, const OwnershipJournal &journal) override {
        calls.append("retain-recovery");
        if (retainFails)
            return false;
        recoverySnapshot = snapshot;
        recoveryJournal = journal;
        return true;
    }
};

class M4NetworkTests : public QObject {
    Q_OBJECT

  private:
    static QByteArray fixture(const char *name) {
        QFile file(QFINDTESTDATA(QString("fixtures/m4/%1.hex").arg(name)));
        if (!file.open(QIODevice::ReadOnly))
            qFatal("Cannot open synthetic ARP fixture");
        return QByteArray::fromHex(file.readAll());
    }
    static SessionConfig validConfig() {
        return {"synthetic0", "192.0.2.10", "192.0.2.30", 18081, {"/api/generate"}, false};
    }
    static NetworkFacts validFacts() {
        NetworkFacts facts;
        facts.interfaceName = "synthetic0";
        facts.researchIp = "192.0.2.20";
        facts.researchMac = "02:00:00:00:00:20";
        facts.clientMac = "02:00:00:00:00:10";
        facts.serverMac = "02:00:00:00:00:30";
        facts.proxyServerIp = "192.0.2.30";
        facts.proxyServerPort = 18081;
        facts.proxyListenPort = 11434;
        facts.interfaceUp = facts.sameLink = facts.anchorAttached = facts.proxyReady =
            facts.authorized = true;
        return facts;
    }
    static SessionSnapshot validSnapshot() {
        const auto snapshot =
            SessionSnapshot::create(validConfig(), validFacts(), 11434, "offline-test");
        if (!snapshot)
            qFatal("Cannot construct synthetic network-session snapshot");
        return *snapshot;
    }
    static VerifiedPeer trustedPeer() {
        return {501, QByteArray("synthetic-verified-audit-identity"), true};
    }
    static QByteArray capability() { return QByteArray(32, 'a'); }
    static HelperCommand command(HelperCommand::Type type, qint64 nowMs = 100) {
        HelperCommand request;
        request.type = type;
        request.capability = capability();
        request.anchor = validSnapshot().anchor();
        request.nowMs = nowMs;
        if (type == HelperCommand::Type::Start)
            request.snapshot = validSnapshot();
        return request;
    }

  private slots:
    void arpFixtureFieldsAndEncoding() {
        const auto bytes = fixture("arp-request");
        QCOMPARE(bytes.size(), qsizetype(42));
        QString error;
        const auto request = ArpCodec::parse(bytes, &error);
        QVERIFY2(request.has_value(), qPrintable(error));
        QCOMPARE(request->operation, quint16(1));
        QCOMPARE(request->senderIp, QString("192.0.2.10"));
        QCOMPARE(request->targetIp, QString("192.0.2.30"));
        QCOMPARE(request->senderMac, QByteArray::fromHex("020000000010"));
        QCOMPARE(request->targetMac, QByteArray(6, '\0'));
        QCOMPARE(request->ethernetDestination, QByteArray(6, char(0xff)));
        const auto encoded = ArpCodec::encode(*request, &error);
        QVERIFY2(!encoded.isEmpty(), qPrintable(error));
        QCOMPARE(encoded.left(42), bytes);
        const auto reply = ArpCodec::parse(fixture("arp-reply"), &error);
        QVERIFY2(reply.has_value(), qPrintable(error));
        QCOMPARE(reply->operation, quint16(2));
        QCOMPARE(reply->senderIp, QString("192.0.2.30"));
        QCOMPARE(reply->senderMac, QByteArray::fromHex("020000000020"));
        QCOMPARE(reply->targetIp, QString("192.0.2.10"));
        QCOMPARE(ArpCodec::encode(*reply, &error).left(42), fixture("arp-reply"));
    }

    void everyTruncationIsRejectedAndPaddingIsAllowed() {
        const auto bytes = fixture("arp-request");
        for (qsizetype size = 0; size < bytes.size(); ++size) {
            QString error;
            QVERIFY(!ArpCodec::parse(bytes.left(size), &error).has_value());
            QVERIFY2(!error.isEmpty(),
                     qPrintable(QString("Missing error for prefix %1").arg(size)));
        }
        const auto padded = ArpCodec::parse(bytes + QByteArray(18, '\0'));
        QVERIFY(padded.has_value());
        QCOMPARE(padded->targetIp, QString("192.0.2.30"));
    }

    void unsupportedAndMalformedArpHeadersAreRejected() {
        const auto original = fixture("arp-request");
        const QList<QPair<int, char>> mutations{{12, char(0x81)}, {14, char(1)},  {16, char(0x86)},
                                                {18, char(5)},    {19, char(16)}, {21, char(3)}};
        for (const auto &mutation : mutations) {
            auto bytes = original;
            bytes[mutation.first] = mutation.second;
            QString error;
            QVERIFY(!ArpCodec::parse(bytes, &error).has_value());
            QVERIFY(!error.isEmpty());
        }
    }

    void encodingRejectsInvalidLengthsAddressesAndOperations() {
        const auto valid = ArpCodec::parse(fixture("arp-request"));
        QVERIFY(valid.has_value());
        auto bad = *valid;
        bad.senderMac = QByteArray(5, '\0');
        QVERIFY(ArpCodec::encode(bad).isEmpty());
        bad = *valid;
        bad.ethernetDestination = QByteArray(7, '\0');
        QVERIFY(ArpCodec::encode(bad).isEmpty());
        bad = *valid;
        bad.senderIp = "not-an-ip";
        QVERIFY(ArpCodec::encode(bad).isEmpty());
        bad = *valid;
        bad.targetIp = "::1";
        QVERIFY(ArpCodec::encode(bad).isEmpty());
        bad = *valid;
        bad.operation = 99;
        QVERIFY(ArpCodec::encode(bad).isEmpty());
    }

    void snapshotFreezesInputsAndScopesNondefaultPort() {
        auto config = validConfig();
        auto facts = validFacts();
        QString error;
        const auto snapshot = SessionSnapshot::create(config, facts, 11434, "offline-test", &error);
        QVERIFY2(snapshot.has_value(), qPrintable(error));
        config.serverIp = "198.51.100.30";
        config.serverPort = 12345;
        facts.interfaceName = "changed0";
        QCOMPARE(snapshot->config().serverIp, QString("192.0.2.30"));
        QCOMPARE(snapshot->config().serverPort, 18081);
        QCOMPARE(snapshot->facts().interfaceName, QString("synthetic0"));
        QCOMPARE(snapshot->proxyPort(), 11434);
        const auto rules = snapshot->pfRules();
        QVERIFY(rules.contains(
            "rdr on \"synthetic0\" inet proto tcp from 192.0.2.10 to 192.0.2.30 port 18081"));
        QVERIFY(rules.contains("127.0.0.1 port 11434"));
        QVERIFY(!rules.contains("com.apple"));
        QVERIFY(!rules.contains("flush"));
        QVERIFY(!rules.contains("from any"));
        // Upstream originates from the research IP, so it cannot match the client-source rule.
        QVERIFY(snapshot->facts().researchIp != snapshot->config().clientIp);
        QVERIFY(!rules.split('\n').front().contains("from 192.0.2.20"));
        QVERIFY(rules.contains("pass out quick on \"synthetic0\" inet proto tcp from 192.0.2.20 to "
                               "192.0.2.30 port 18081"));
        QVERIFY(snapshot->anchor().contains("offline-test"));
    }

    void invalidTopologyAndFactsNeverCreateSnapshot() {
        for (int field = 0; field < 6; ++field) {
            auto facts = validFacts();
            switch (field) {
            case 0:
                facts.interfaceUp = false;
                break;
            case 1:
                facts.sameLink = false;
                break;
            case 2:
                facts.anchorAttached = false;
                break;
            case 3:
                facts.proxyReady = false;
                break;
            case 4:
                facts.authorized = false;
                break;
            case 5:
                facts.interfaceName = "different0";
                break;
            }
            QString error;
            QVERIFY(!SessionSnapshot::create(validConfig(), facts, 11434, "offline-test", &error));
            QVERIFY(!error.isEmpty());
        }
        auto facts = validFacts();
        facts.researchIp = "192.0.2.10";
        QVERIFY(!SessionSnapshot::create(validConfig(), facts, 11434, "offline-test"));
        facts = validFacts();
        facts.researchIp = "198.51.100.20";
        QVERIFY(!SessionSnapshot::create(validConfig(), facts, 11434, "offline-test"));
        facts = validFacts();
        facts.clientMac = "ff:ff:ff:ff:ff:ff";
        QVERIFY(!SessionSnapshot::create(validConfig(), facts, 11434, "offline-test"));
        facts = validFacts();
        facts.clientMac = facts.serverMac;
        QVERIFY(!SessionSnapshot::create(validConfig(), facts, 11434, "offline-test"));
        facts = validFacts();
        facts.prefixLength = 33;
        QVERIFY(!SessionSnapshot::create(validConfig(), facts, 11434, "offline-test"));
        QVERIFY(!SessionSnapshot::create(validConfig(), validFacts(), 0, "offline-test"));
        QVERIFY(!SessionSnapshot::create(validConfig(), validFacts(), 11434, "../unsafe\nanchor"));
        auto config = validConfig();
        config.interfaceName = "synthetic0\nrdr pass";
        QVERIFY(!SessionSnapshot::create(config, validFacts(), 11434, "offline-test"));
        config = validConfig();
        config.serverPort = 65536;
        QVERIFY(!SessionSnapshot::create(config, validFacts(), 11434, "offline-test"));
    }

    void readinessMustMatchBothUpstreamAndLocalListener() {
        for (int field = 0; field < 3; ++field) {
            auto facts = validFacts();
            if (field == 0)
                facts.proxyServerIp = "198.51.100.30";
            else if (field == 1)
                facts.proxyServerPort = 11434;
            else
                facts.proxyListenPort = 18082;
            QString error;
            QVERIFY(!SessionSnapshot::create(validConfig(), facts, 11434, "offline-test", &error));
            QVERIFY(!error.isEmpty());
        }
        QVERIFY(!SessionSnapshot::create(validConfig(), NetworkFacts{}, 0, "offline-test"));
        auto facts = validFacts();
        facts.proxyListenPort = validConfig().serverPort;
        const auto equalPort =
            SessionSnapshot::create(validConfig(), facts, validConfig().serverPort, "equal-port");
        QVERIFY(equalPort.has_value());
        QVERIFY(equalPort->pfRules().split('\n').front().contains(
            "from 192.0.2.10 to 192.0.2.30 port 18081"));
    }

    void bidirectionalSyntheticArpFramesStayWithinSelectedPair() {
        const auto snapshot = validSnapshot();
        const auto redirected = snapshot.redirectionFrames();
        const auto restored = snapshot.restorationFrames();
        QCOMPARE(redirected.size(), qsizetype(2));
        QCOMPARE(restored.size(), qsizetype(2));
        for (int direction = 0; direction < 2; ++direction) {
            const auto redirect = ArpCodec::parse(redirected[direction]);
            const auto restore = ArpCodec::parse(restored[direction]);
            QVERIFY(redirect.has_value());
            QVERIFY(restore.has_value());
            const auto recipient =
                QByteArray::fromHex(direction == 0 ? "020000000010" : "020000000030");
            const auto actualPeer =
                QByteArray::fromHex(direction == 0 ? "020000000030" : "020000000010");
            const QString senderIp = direction == 0 ? "192.0.2.30" : "192.0.2.10";
            const QString recipientIp = direction == 0 ? "192.0.2.10" : "192.0.2.30";
            QCOMPARE(redirect->operation, quint16(2));
            QCOMPARE(restore->operation, quint16(2));
            QCOMPARE(redirect->ethernetDestination, recipient);
            QCOMPARE(restore->ethernetDestination, recipient);
            QCOMPARE(redirect->targetMac, recipient);
            QCOMPARE(restore->targetMac, recipient);
            QCOMPARE(redirect->senderIp, senderIp);
            QCOMPARE(restore->senderIp, senderIp);
            QCOMPARE(redirect->targetIp, recipientIp);
            QCOMPARE(restore->targetIp, recipientIp);
            QCOMPARE(redirect->senderMac, QByteArray::fromHex("020000000020"));
            QCOMPARE(restore->senderMac, actualPeer);
        }
    }

    void normalLifecycleRestoresOnlyOwnedResources() {
        FakeSystemOperations fake;
        NetworkSession session(fake);
        QSignalSpy changes(&session, &NetworkSession::stateChanged);
        QVERIFY(session.start(validSnapshot(), 100));
        QCOMPARE(session.state(), NetworkSession::State::Active);
        QVERIFY(session.snapshot().has_value());
        QCOMPARE(fake.forwarding, 1);
        QCOMPARE(fake.redirects, 0);
        QVERIFY(fake.arpActive);
        QVERIFY(!session.start(validSnapshot(), 200));
        QVERIFY(session.stop());
        QCOMPARE(session.state(), NetworkSession::State::Idle);
        QVERIFY(session.journal().empty());
        QCOMPARE(fake.forwarding, 0);
        QCOMPARE(fake.redirects, 1);
        QVERIFY(!fake.arpActive);
        QVERIFY(!fake.neighborsChanged);
        QCOMPARE(fake.references, QSet<QString>({"foreign-reference"}));
        QCOMPARE(fake.anchors, QSet<QString>({"foreign-anchor"}));
        QCOMPARE(fake.states, QSet<QString>({"foreign-state"}));
        QCOMPARE(fake.calls.count("release:owned-reference"), 1);
        QVERIFY(!fake.calls.contains("release:foreign-reference"));
        QVERIFY(fake.calls.indexOf("end-arp") < fake.calls.indexOf("restore-neighbors"));
        QVERIFY(fake.calls.indexOf("restore-neighbors") < fake.calls.indexOf("remove-anchor"));
        QVERIFY(fake.calls.indexOf("remove-anchor") < fake.calls.indexOf("clear-owned-state"));
        QVERIFY(fake.calls.indexOf("release:owned-reference") <
                fake.calls.indexOf("release-lease"));
        QVERIFY(fake.activeLease.isEmpty());
        const auto callsBefore = fake.calls.size();
        QVERIFY(session.stop());
        QCOMPARE(fake.calls.size(), callsBefore);
        QVERIFY(changes.count() >= 4);
    }

    void eachStartupFailureRollsBackPartialMutations() {
        for (const auto &failure : {"acquire-lease", "interface-available", "read-forwarding",
                                    "read-redirects", "cas-forwarding:0->1", "cas-redirects:1->0",
                                    "acquire-reference", "install-anchor", "begin-arp"}) {
            FakeSystemOperations fake;
            fake.failure = failure;
            NetworkSession session(fake);
            QVERIFY2(!session.start(validSnapshot(), 100), failure);
            QCOMPARE(session.state(), NetworkSession::State::Idle);
            QVERIFY2(session.journal().empty(), failure);
            QCOMPARE(fake.forwarding, 0);
            QCOMPARE(fake.redirects, 1);
            QVERIFY(!fake.arpActive);
            QVERIFY(!fake.neighborsChanged);
            QCOMPARE(fake.references, QSet<QString>({"foreign-reference"}));
            QCOMPARE(fake.anchors, QSet<QString>({"foreign-anchor"}));
            QCOMPARE(fake.states, QSet<QString>({"foreign-state"}));
            QVERIFY(fake.activeLease.isEmpty());
            QVERIFY(!session.status().isEmpty());
        }
    }

    void cleanupFailuresRemainRetryable() {
        for (const auto &failure :
             {"end-arp", "restore-neighbors", "clear-owned-state", "remove-anchor",
              "read-forwarding", "read-redirects", "cas-forwarding:1->0", "cas-redirects:0->1",
              "release:owned-reference", "release-lease"}) {
            FakeSystemOperations fake;
            NetworkSession session(fake);
            QVERIFY(session.start(validSnapshot(), 100));
            fake.failure = failure;
            QVERIFY2(!session.stop(), failure);
            QCOMPARE(session.state(), NetworkSession::State::CleanupPending);
            QVERIFY(!session.journal().empty());
            QVERIFY(session.journal().sessionLease.has_value());
            QVERIFY(!fake.activeLease.isEmpty());
            QVERIFY(!session.start(validSnapshot(), 200));
            QVERIFY(session.stop());
            QCOMPARE(session.state(), NetworkSession::State::Idle);
            QVERIFY(session.journal().empty());
            QCOMPARE(fake.forwarding, 0);
            QCOMPARE(fake.redirects, 1);
            QCOMPARE(fake.references, QSet<QString>({"foreign-reference"}));
            QCOMPARE(fake.anchors, QSet<QString>({"foreign-anchor"}));
            QCOMPARE(fake.states, QSet<QString>({"foreign-state"}));
            QVERIFY(!fake.arpActive);
            QVERIFY(!fake.neighborsChanged);
            QVERIFY(fake.activeLease.isEmpty());
        }
    }

    void concurrentSettingChangesAreNotOverwritten() {
        FakeSystemOperations fake;
        NetworkSession session(fake);
        QVERIFY(session.start(validSnapshot(), 100));
        fake.forwarding = 2; // A distinct value models an unrelated setting owner.
        const auto restoredBefore = fake.calls.count("cas-forwarding:1->0");
        QVERIFY(!session.stop());
        QCOMPARE(session.state(), NetworkSession::State::CleanupPending);
        QCOMPARE(fake.forwarding, 2);
        QCOMPARE(fake.calls.count("cas-forwarding:1->0"), restoredBefore);
        QVERIFY(session.journal().previousForwarding.has_value());
        QVERIFY(!session.status().isEmpty());
        fake.forwarding = 1;
        QVERIFY(session.stop());
        QCOMPARE(fake.forwarding, 0);
        QVERIFY(session.journal().empty());
    }

    void watchdogAndInterfaceLossTriggerScopedCleanup() {
        FakeSystemOperations fake;
        NetworkSession session(fake);
        QVERIFY(session.start(validSnapshot(), 100));
        session.heartbeat(1000);
        QVERIFY(session.checkWatchdog(5999));
        QCOMPARE(session.state(), NetworkSession::State::Active);
        session.heartbeat(500); // A stale heartbeat cannot move the clock backward.
        QVERIFY(!session.checkWatchdog(6000));
        QCOMPARE(session.state(), NetworkSession::State::Idle);
        QVERIFY(session.journal().empty());
        QVERIFY(session.start(validSnapshot(), 7000));
        fake.available = false;
        QVERIFY(!session.checkWatchdog(7001));
        QCOMPARE(session.state(), NetworkSession::State::Idle);
        QVERIFY(session.journal().empty());
        fake.available = true;
        QVERIFY(session.start(validSnapshot(), 8000));
        QVERIFY(session.interfaceLost());
        QCOMPARE(session.state(), NetworkSession::State::Idle);
        QCOMPARE(fake.references, QSet<QString>({"foreign-reference"}));
    }

    void atomicRestoreDetectsConcurrentChangeAfterRead() {
        FakeSystemOperations fake;
        NetworkSession session(fake);
        QVERIFY(session.start(validSnapshot(), 100));
        fake.changeDuringRestore = true;
        QVERIFY(!session.stop());
        QCOMPARE(fake.forwarding, 2);
        QCOMPARE(session.state(), NetworkSession::State::CleanupPending);
        QVERIFY(session.journal().previousForwarding.has_value());
        QVERIFY(session.journal().sessionLease.has_value());
        fake.forwarding = 1;
        QVERIFY(session.stop());
        QCOMPARE(fake.forwarding, 0);
        QVERIFY(fake.activeLease.isEmpty());
    }

    void exclusiveLeasePreventsConcurrentHelpers() {
        FakeSystemOperations fake;
        NetworkSession first(fake), second(fake);
        QVERIFY(first.start(validSnapshot(), 100));
        const auto token = first.journal().sessionLease;
        QVERIFY(!second.start(validSnapshot(), 200));
        QCOMPARE(second.state(), NetworkSession::State::Idle);
        QVERIFY(second.journal().empty());
        QCOMPARE(first.journal().sessionLease, token);
        QVERIFY(fake.arpActive);
        QVERIFY(first.stop());
        QVERIFY(second.start(validSnapshot(), 300));
        QVERIFY(second.journal().sessionLease != token);
        QVERIFY(second.stop());
    }

    void scopeExitBestEffortCleanupRestoresSyntheticState() {
        FakeSystemOperations fake;
        {
            NetworkSession session(fake);
            QVERIFY(session.start(validSnapshot(), 100));
        }
        QVERIFY(!fake.arpActive);
        QVERIFY(!fake.neighborsChanged);
        QVERIFY(fake.activeLease.isEmpty());
        QCOMPARE(fake.references, QSet<QString>({"foreign-reference"}));
        QCOMPARE(fake.anchors, QSet<QString>({"foreign-anchor"}));
        QCOMPARE(fake.states, QSet<QString>({"foreign-state"}));
        QCOMPARE(fake.forwarding, 0);
        QCOMPARE(fake.redirects, 1);
    }

    void failedScopeExitReportsBackendRecoveryOwnership() {
        FakeSystemOperations fake;
        fake.partialFailure = false;
        OwnershipJournal before;
        {
            NetworkSession session(fake);
            QVERIFY(session.start(validSnapshot(), 100));
            before = session.journal();
            fake.failure = "end-arp";
            QTest::ignoreMessage(QtWarningMsg, "Offline helper destroyed with cleanup pending; "
                                               "recovery journal transferred to backend");
        }
        QVERIFY(fake.arpActive);
        QVERIFY(fake.neighborsChanged);
        QVERIFY(!fake.activeLease.isEmpty());
        QVERIFY(fake.references.contains("owned-reference"));
        QVERIFY(fake.anchors.contains(validSnapshot().anchor()));
        QVERIFY(fake.states.contains(validSnapshot().anchor()));
        QVERIFY(fake.recoverySnapshot.has_value());
        QVERIFY(fake.recoveryJournal.has_value());
        QCOMPARE(fake.recoverySnapshot->pfRules(), validSnapshot().pfRules());
        QCOMPARE(fake.recoverySnapshot->config().serverPort, validSnapshot().config().serverPort);
        const auto recovered = *fake.recoveryJournal;
        QCOMPARE(recovered.previousForwarding, before.previousForwarding);
        QCOMPARE(recovered.previousSendRedirects, before.previousSendRedirects);
        QCOMPARE(recovered.pfToken, before.pfToken);
        QCOMPARE(recovered.sessionLease, before.sessionLease);
        QCOMPARE(recovered.anchor, before.anchor);
        QCOMPARE(recovered.state, before.state);
        QCOMPARE(recovered.arp, before.arp);
        QCOMPARE(recovered.neighbors, before.neighbors);
        // The long-lived fake owns enough synthetic state to retry scoped recovery.
        // A durable OS backend and crash recovery remain unverified M6 work.
        const auto snapshot = validSnapshot();
        QVERIFY(fake.endArp(snapshot));
        QVERIFY(fake.restoreNeighbors(snapshot));
        QVERIFY(fake.removeAnchor(snapshot));
        QVERIFY(fake.clearOwnedState(snapshot));
        QCOMPARE(fake.compareAndSetSetting(NetworkSetting::SendRedirects, 0, 1),
                 SettingChange::Applied);
        QCOMPARE(fake.compareAndSetSetting(NetworkSetting::Forwarding, 1, 0),
                 SettingChange::Applied);
        QVERIFY(fake.releasePfReference("owned-reference"));
        QVERIFY(fake.releaseSessionLease(fake.activeLease));
        QVERIFY(!fake.arpActive);
        QVERIFY(fake.activeLease.isEmpty());
        QCOMPARE(fake.references, QSet<QString>({"foreign-reference"}));
    }

    void failedRecoveryRetentionIsExplicitlyDiagnosed() {
        FakeSystemOperations fake;
        fake.partialFailure = false;
        fake.retainFails = true;
        {
            NetworkSession session(fake);
            QVERIFY(session.start(validSnapshot(), 100));
            fake.failure = "end-arp";
            QTest::ignoreMessage(
                QtWarningMsg,
                "Offline helper destroyed with cleanup pending; recovery journal retention failed");
        }
        QVERIFY(fake.calls.contains("retain-recovery"));
        QVERIFY(!fake.recoveryJournal.has_value());
        QVERIFY(!fake.recoverySnapshot.has_value());
        QVERIFY(fake.arpActive);
        QVERIFY(!fake.activeLease.isEmpty());
    }

    void dispatcherRejectsUnverifiedPeersTokensAndMalformedCommandsBeforeEffects() {
        FakeSystemOperations fake;
        HelperDispatcher dispatcher(fake, validSnapshot(), trustedPeer(), capability());
        QVERIFY(dispatcher.ready());
        const auto *sessionChild = dispatcher.findChild<NetworkSession *>();
        QVERIFY(sessionChild);
        QCOMPARE(sessionChild->parent(), static_cast<QObject *>(&dispatcher));
        QCOMPARE(sessionChild->thread(), dispatcher.thread());
        for (int field = 0; field < 3; ++field) {
            auto peer = trustedPeer();
            if (field == 0)
                peer.transportAuthenticated = false;
            else if (field == 1)
                ++peer.uid;
            else
                peer.auditIdentity = "different-verified-process";
            QVERIFY(!dispatcher.dispatch(peer, command(HelperCommand::Type::Start)));
            QVERIFY(fake.calls.isEmpty());
        }
        for (int field = 0; field < 5; ++field) {
            auto request = command(HelperCommand::Type::Start);
            switch (field) {
            case 0:
                request.capability = QByteArray(32, 'b');
                break;
            case 1:
                request.anchor = "foreign-anchor";
                break;
            case 2:
                request.type = static_cast<HelperCommand::Type>(999);
                break;
            case 3:
                request.nowMs = -1;
                break;
            case 4:
                request.snapshot.reset();
                break;
            }
            QVERIFY(!dispatcher.dispatch(trustedPeer(), request));
            QVERIFY(fake.calls.isEmpty());
        }
        auto request = command(HelperCommand::Type::Stop);
        request.snapshot = validSnapshot();
        QVERIFY(!dispatcher.dispatch(trustedPeer(), request));
        QVERIFY(fake.calls.isEmpty());
    }

    void dispatcherRejectsDifferentFrozenRoutesMacsAndApiScope() {
        FakeSystemOperations fake;
        HelperDispatcher dispatcher(fake, validSnapshot(), trustedPeer(), capability());
        for (int field = 0; field < 3; ++field) {
            auto config = validConfig();
            auto facts = validFacts();
            if (field == 0) {
                config.serverPort = 18082;
                facts.proxyServerPort = 18082;
            } else if (field == 1) {
                facts.clientMac = "02:00:00:00:00:11";
            } else {
                config.apiPaths = {"/api/chat"};
            }
            const auto alternative = SessionSnapshot::create(config, facts, 11434, "offline-test");
            QVERIFY(alternative.has_value());
            auto request = command(HelperCommand::Type::Start);
            request.snapshot = alternative;
            QVERIFY(!dispatcher.dispatch(trustedPeer(), request));
            QVERIFY(fake.calls.isEmpty());
        }
    }

    void authorizedDispatcherLifecycleAndClockValidation() {
        FakeSystemOperations fake;
        HelperDispatcher dispatcher(fake, validSnapshot(), trustedPeer(), capability());
        QVERIFY(dispatcher.dispatch(trustedPeer(), command(HelperCommand::Type::Start, 100)));
        QCOMPARE(dispatcher.state(), NetworkSession::State::Active);
        const auto mutations = fake.calls.size();
        auto wrongStop = command(HelperCommand::Type::Stop, 200);
        wrongStop.capability = QByteArray(32, 'b');
        QVERIFY(!dispatcher.dispatch(trustedPeer(), wrongStop));
        QCOMPARE(fake.calls.size(), mutations);
        QCOMPARE(dispatcher.state(), NetworkSession::State::Active);
        QVERIFY(dispatcher.dispatch(trustedPeer(), command(HelperCommand::Type::Heartbeat, 1000)));
        const auto before = fake.calls.size();
        QVERIFY(!dispatcher.dispatch(trustedPeer(), command(HelperCommand::Type::Heartbeat, 999)));
        QVERIFY(!dispatcher.dispatch(trustedPeer(), command(HelperCommand::Type::Watchdog, 999)));
        QCOMPARE(fake.calls.size(), before);
        QVERIFY(dispatcher.dispatch(trustedPeer(), command(HelperCommand::Type::Watchdog, 5999)));
        QCOMPARE(dispatcher.state(), NetworkSession::State::Active);
        QVERIFY(dispatcher.dispatch(trustedPeer(), command(HelperCommand::Type::Stop, 6000)));
        QCOMPARE(dispatcher.state(), NetworkSession::State::Idle);
        QVERIFY(dispatcher.journal().empty());
        QCOMPARE(fake.references, QSet<QString>({"foreign-reference"}));
        const auto after = fake.calls.size();
        QVERIFY(!dispatcher.dispatch(trustedPeer(), command(HelperCommand::Type::Stop, 6000)));
        QVERIFY(!dispatcher.dispatch(trustedPeer(), command(HelperCommand::Type::Start, 6001)));
        QCOMPARE(fake.calls.size(), after);
        QVERIFY(!dispatcher.ready());
    }

    void invalidDispatcherTrustConfigurationFailsClosed() {
        FakeSystemOperations fake;
        auto peer = trustedPeer();
        peer.transportAuthenticated = false;
        HelperDispatcher untrusted(fake, validSnapshot(), peer, capability());
        QVERIFY(!untrusted.ready());
        QVERIFY(!untrusted.dispatch(trustedPeer(), command(HelperCommand::Type::Start)));
        HelperDispatcher badCapability(fake, validSnapshot(), trustedPeer(), QByteArray(1, 'a'));
        QVERIFY(!badCapability.ready());
        QVERIFY(!badCapability.dispatch(trustedPeer(), command(HelperCommand::Type::Start)));
        QVERIFY(fake.calls.isEmpty());
    }

    void dispatcherExpiryRevokesCapabilityAndPendingCleanupCanRetry() {
        {
            FakeSystemOperations fake;
            HelperDispatcher dispatcher(fake, validSnapshot(), trustedPeer(), capability());
            QVERIFY(dispatcher.dispatch(trustedPeer(), command(HelperCommand::Type::Start, 100)));
            QVERIFY(
                !dispatcher.dispatch(trustedPeer(), command(HelperCommand::Type::Watchdog, 5100)));
            QCOMPARE(dispatcher.state(), NetworkSession::State::Idle);
            QVERIFY(dispatcher.journal().empty());
            const auto calls = fake.calls.size();
            QVERIFY(!dispatcher.dispatch(trustedPeer(), command(HelperCommand::Type::Start, 5101)));
            QCOMPARE(fake.calls.size(), calls);
            QVERIFY(!dispatcher.ready());
        }
        {
            FakeSystemOperations fake;
            fake.partialFailure = false;
            HelperDispatcher dispatcher(fake, validSnapshot(), trustedPeer(), capability());
            QVERIFY(dispatcher.dispatch(trustedPeer(), command(HelperCommand::Type::Start, 100)));
            fake.failure = "end-arp";
            QVERIFY(!dispatcher.dispatch(trustedPeer(), command(HelperCommand::Type::Stop, 200)));
            QCOMPARE(dispatcher.state(), NetworkSession::State::CleanupPending);
            QVERIFY(dispatcher.ready());
            QVERIFY(!dispatcher.journal().empty());
            QVERIFY(dispatcher.dispatch(trustedPeer(), command(HelperCommand::Type::Stop, 201)));
            QCOMPARE(dispatcher.state(), NetworkSession::State::Idle);
            QVERIFY(dispatcher.journal().empty());
            const auto calls = fake.calls.size();
            QVERIFY(!dispatcher.dispatch(trustedPeer(), command(HelperCommand::Type::Start, 202)));
            QCOMPARE(fake.calls.size(), calls);
            QVERIFY(!dispatcher.ready());
        }
    }
};

QTEST_GUILESS_MAIN(M4NetworkTests)
#include "M4NetworkTests.moc"
