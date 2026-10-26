#include "network/HelperDispatcher.hpp"
#include "network/HelperSessionIdentity.hpp"

#include <QtTest>

#include <array>
#include <cstring>
#include <memory>
#include <type_traits>

namespace interceptor {

static_assert(!std::is_copy_constructible_v<HelperSessionIdentity>);
static_assert(std::is_move_constructible_v<HelperSessionIdentity>);

class IdentityTestOperations final : public SystemOperations {
  public:
    std::optional<int> readSetting(NetworkSetting) override { return 0; }
    SettingChange compareAndSetSetting(NetworkSetting, int, int) override {
        return SettingChange::Unchanged;
    }
    std::optional<QString> acquireSessionLease(const SessionSnapshot &) override {
        return QStringLiteral("synthetic-lease");
    }
    bool releaseSessionLease(const QString &) override { return true; }
    std::optional<QString> acquirePfReference() override { return QStringLiteral("synthetic-pf"); }
    bool releasePfReference(const QString &) override { return true; }
    bool installAnchor(const SessionSnapshot &) override { return true; }
    bool removeAnchor(const SessionSnapshot &) override { return true; }
    bool clearOwnedState(const SessionSnapshot &) override { return true; }
    bool beginArp(const SessionSnapshot &) override { return true; }
    bool endArp(const SessionSnapshot &) override { return true; }
    bool restoreNeighbors(const SessionSnapshot &) override { return true; }
    bool interfaceAvailable(const SessionSnapshot &) override { return true; }
    bool retainRecovery(const SessionSnapshot &, const OwnershipJournal &) override { return true; }
};

class M6HelperSessionIdentityTests : public QObject {
    Q_OBJECT

  private:
    static QByteArray sequence(std::size_t count, unsigned char start) {
        QByteArray result;
        result.reserve(static_cast<qsizetype>(count));
        for (std::size_t index = 0; index < count; ++index)
            result.append(static_cast<char>(start + static_cast<unsigned char>(index)));
        return result;
    }

    static HelperSessionIdentity::EntropySource sourceFor(const QByteArray &sessionBytes,
                                                          const QByteArray &capabilityBytes) {
        auto calls = std::make_shared<int>(0);
        return
            [sessionBytes, capabilityBytes, calls](unsigned char *destination, std::size_t length) {
                const QByteArray &source = (*calls)++ == 0 ? sessionBytes : capabilityBytes;
                if (destination == nullptr || length != static_cast<std::size_t>(source.size()))
                    return false;
                std::memcpy(destination, source.constData(), source.size());
                return true;
            };
    }

    static SessionSnapshot snapshot(const QString &sessionId) {
        SessionConfig config{"en0", "192.0.2.10", "192.0.2.30", 18081, {"/api/generate"}, false};
        NetworkFacts facts;
        facts.interfaceName = "en0";
        facts.researchIp = "192.0.2.20";
        facts.researchMac = "02:00:00:00:00:20";
        facts.clientMac = "02:00:00:00:00:10";
        facts.serverMac = "02:00:00:00:00:30";
        facts.proxyServerIp = "192.0.2.30";
        facts.proxyServerPort = 18081;
        facts.proxyListenPort = 11434;
        facts.interfaceUp = facts.sameLink = facts.anchorAttached = facts.proxyReady =
            facts.authorized = true;
        const auto created = SessionSnapshot::create(config, facts, 11434, sessionId);
        if (!created)
            qFatal("Unable to create synthetic identity snapshot");
        return *created;
    }

    static VerifiedPeer peer() { return {501, QByteArrayLiteral("synthetic-peer"), true}; }

    static HelperCommand stopCommand(const SessionSnapshot &permitted,
                                     const QByteArray &capability) {
        HelperCommand command;
        command.type = HelperCommand::Type::Stop;
        command.capability = capability;
        command.anchor = permitted.anchor();
        return command;
    }

  private slots:
    void fixedEntropyProducesLowerHexSessionIdAndBinaryCapability() {
        const QByteArray sessionBytes = sequence(HelperSessionIdentity::sessionRandomBytes, 0x00);
        const QByteArray capabilityBytes =
            sequence(HelperSessionIdentity::capabilityRandomBytes, 0x80);
        QVector<std::size_t> requestedLengths;
        const HelperSessionIdentity::EntropySource entropy = [&](unsigned char *destination,
                                                                 std::size_t length) {
            requestedLengths.append(length);
            const auto &source = requestedLengths.size() == 1 ? sessionBytes : capabilityBytes;
            if (destination == nullptr || length != static_cast<std::size_t>(source.size()))
                return false;
            std::memcpy(destination, source.constData(), source.size());
            return true;
        };

        auto identity = HelperSessionIdentity::createWithEntropy(entropy);
        QVERIFY(identity.has_value());
        QCOMPARE(requestedLengths, QVector<std::size_t>({16, 32}));
        QCOMPARE(identity->sessionId(), QString::fromLatin1(sessionBytes.toHex()));
        QCOMPARE(identity->sessionId().size(), 32);
        QVERIFY(
            identity->sessionId().contains(QRegularExpression(QStringLiteral("^[0-9a-f]{32}$"))));
        QByteArray capability = std::move(*identity).takeCapability();
        QCOMPARE(capability, capabilityBytes);
        QCOMPARE(capability.size(), 32);
    }

    void differentEntropyProducesDifferentSessionAndCapability() {
        auto first = HelperSessionIdentity::createWithEntropy(
            sourceFor(sequence(16, 0x01), sequence(32, 0x11)));
        auto second = HelperSessionIdentity::createWithEntropy(
            sourceFor(sequence(16, 0x02), sequence(32, 0x12)));
        QVERIFY(first.has_value());
        QVERIFY(second.has_value());
        QVERIFY(first->sessionId() != second->sessionId());
        const QByteArray firstCapability = std::move(*first).takeCapability();
        const QByteArray secondCapability = std::move(*second).takeCapability();
        QVERIFY(firstCapability != secondCapability);
    }

    void moveConstructionTransfersIdentityValues() {
        const QByteArray expectedSession = sequence(16, 0x41).toHex();
        const QByteArray expectedCapability = sequence(32, 0xa1);
        auto original = HelperSessionIdentity::createWithEntropy(
            sourceFor(sequence(16, 0x41), expectedCapability));
        QVERIFY(original.has_value());
        HelperSessionIdentity moved(std::move(*original));
        QCOMPARE(moved.sessionId().toLatin1(), expectedSession);
        const QByteArray movedCapability = std::move(moved).takeCapability();
        QCOMPARE(movedCapability, expectedCapability);
    }

    void entropyFailureReturnsNoPartialIdentity() {
        const QByteArray sessionBytes = sequence(16, 0x20);
        int calls = 0;
        const HelperSessionIdentity::EntropySource failsOnCapability =
            [&](unsigned char *destination, std::size_t length) {
                ++calls;
                if (calls == 1 && destination != nullptr && length == 16) {
                    std::memcpy(destination, sessionBytes.constData(), sessionBytes.size());
                    return true;
                }
                if (destination != nullptr && length == 32)
                    std::memset(destination, 0x5a, length);
                return false;
            };
        const auto failed = HelperSessionIdentity::createWithEntropy(failsOnCapability);
        QVERIFY(!failed.has_value());
        QCOMPARE(calls, 2);

        const auto firstFailure = HelperSessionIdentity::createWithEntropy(
            [](unsigned char *destination, std::size_t length) {
                if (destination && length)
                    std::memset(destination, 0x5a, length);
                return false;
            });
        QVERIFY(!firstFailure.has_value());
        const auto emptySource = HelperSessionIdentity::createWithEntropy({});
        QVERIFY(!emptySource.has_value());
    }

    void generatedIdPassesSnapshotValidation() {
        auto identity = HelperSessionIdentity::createWithEntropy(
            sourceFor(sequence(16, 0x31), sequence(32, 0x61)));
        QVERIFY(identity.has_value());
        const auto generated = SessionSnapshot::create(
            SessionConfig{"en0", "192.0.2.10", "192.0.2.30", 18081, {"/api/generate"}, false},
            NetworkFacts{.interfaceName = "en0",
                         .researchIp = "192.0.2.20",
                         .researchMac = "02:00:00:00:00:20",
                         .clientMac = "02:00:00:00:00:10",
                         .serverMac = "02:00:00:00:00:30",
                         .proxyServerIp = "192.0.2.30",
                         .proxyServerPort = 18081,
                         .proxyListenPort = 11434,
                         .interfaceUp = true,
                         .sameLink = true,
                         .anchorAttached = true,
                         .proxyReady = true,
                         .authorized = true},
            11434, identity->sessionId());
        QVERIFY(generated.has_value());
        QCOMPARE(generated->sessionId(), identity->sessionId());
    }

    void dispatcherAcceptsExactBinaryCapabilityAndRejectsAlteredTokens() {
        const auto permitted = snapshot(QStringLiteral("identity-dispatch"));
        const auto trustedPeer = peer();
        QByteArray binaryCapability = sequence(32, 0x80);
        binaryCapability[1] = '\0';
        binaryCapability[2] = static_cast<char>(0xff);
        const auto matching = stopCommand(permitted, binaryCapability);

        IdentityTestOperations matchingOperations;
        HelperDispatcher matchingDispatcher(matchingOperations, permitted, trustedPeer,
                                            binaryCapability);
        QVERIFY(matchingDispatcher.ready());
        QVERIFY(matchingDispatcher.dispatch(trustedPeer, matching));

        IdentityTestOperations alteredOperations;
        HelperDispatcher alteredDispatcher(alteredOperations, permitted, trustedPeer,
                                           binaryCapability);
        auto alteredSameLength = stopCommand(permitted, binaryCapability);
        alteredSameLength.capability[10] ^= 0x01;
        QVERIFY(!alteredDispatcher.dispatch(trustedPeer, alteredSameLength));
        QCOMPARE(alteredDispatcher.state(), NetworkSession::State::Idle);

        auto alteredLength = stopCommand(permitted, binaryCapability.left(31));
        QVERIFY(!alteredDispatcher.dispatch(trustedPeer, alteredLength));
        QCOMPARE(alteredDispatcher.state(), NetworkSession::State::Idle);

        for (const qsizetype invalidLength : {qsizetype(33), qsizetype(128)}) {
            auto wrongLength = stopCommand(permitted, QByteArray(invalidLength, 'x'));
            QVERIFY(!alteredDispatcher.dispatch(trustedPeer, wrongLength));
            QCOMPARE(alteredDispatcher.state(), NetworkSession::State::Idle);
        }

        for (const qsizetype invalidLength :
             {qsizetype(31), qsizetype(33), qsizetype(128), qsizetype(129)}) {
            IdentityTestOperations operations;
            HelperDispatcher notReady(operations, permitted, trustedPeer,
                                      QByteArray(invalidLength, 'x'));
            QVERIFY(!notReady.ready());
            QVERIFY(!notReady.dispatch(trustedPeer,
                                       stopCommand(permitted, QByteArray(invalidLength, 'x'))));
        }
    }
};

} // namespace interceptor

QTEST_GUILESS_MAIN(interceptor::M6HelperSessionIdentityTests)
#include "M6HelperSessionIdentityTests.moc"
