#include "network/PfAnchorCleanupVerifier.hpp"

#include <QtTest>

#include <array>

using namespace interceptor;

class FakePfCommandRunner final : public PfCommandRunner {
  public:
    struct Call {
        PfQuery query;
        QString anchor;
        int timeoutMs;
        qsizetype outputLimitBytes;
    };

    std::array<PfQueryOutput, 2> outputs = {PfQueryOutput{PfCommandStatus::Completed, 0, {}},
                                            PfQueryOutput{PfCommandStatus::Completed, 0, {}}};
    QVector<Call> calls;

    PfQueryOutput query(PfQuery requested, const QString &anchor, int timeoutMs,
                        qsizetype outputLimitBytes) override {
        calls.append({requested, anchor, timeoutMs, outputLimitBytes});
        if (requested == PfQuery::SessionFilterRules)
            return outputs[0];
        if (requested == PfQuery::SessionTranslationRules)
            return outputs[1];
        return {};
    }
};

class M6PfAnchorCleanupVerifierTests : public QObject {
    Q_OBJECT

  private:
    static SessionSnapshot snapshot() {
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
        const auto created = SessionSnapshot::create(config, facts, 11434, "cleanup-verifier-a");
        if (!created)
            qFatal("Unable to create synthetic cleanup-verifier snapshot");
        return *created;
    }

    static void verifyCalls(const FakePfCommandRunner &runner, const QString &anchor,
                            int timeoutMs) {
        QCOMPARE(runner.calls.size(), 2);
        QCOMPARE(runner.calls[0].query, PfQuery::SessionFilterRules);
        QCOMPARE(runner.calls[1].query, PfQuery::SessionTranslationRules);
        for (const auto &call : runner.calls) {
            QCOMPARE(call.anchor, anchor);
            QCOMPARE(call.timeoutMs, timeoutMs);
            QCOMPARE(call.outputLimitBytes, PfCommandAnchorCleanupVerifier::maximumOutputBytes);
        }
    }

  private slots:
    void emptyAnchorUsesExactBoundedReadOnlyQueries() {
        FakePfCommandRunner runner;
        runner.outputs[0].standardOutput = " \t\r\n";
        runner.outputs[1].standardOutput = "\v\f\n";
        PfCommandAnchorCleanupVerifier verifier(runner);

        QCOMPARE(verifier.verifyOwnedAnchorEmpty(snapshot()), PfAnchorCleanupVerification::Empty);
        verifyCalls(runner, "llm_interceptor/cleanup-verifier-a",
                    PfCommandAnchorCleanupVerifier::defaultTimeoutMs);
    }

    void validRuleOnEitherAnchorMeansNotEmptyAndStopsEarly() {
        const QByteArray validFilterRule = "@0 pass in quick on en0 inet all\n";
        {
            FakePfCommandRunner runner;
            runner.outputs[0].standardOutput = validFilterRule;
            PfCommandAnchorCleanupVerifier verifier(runner);
            QCOMPARE(verifier.verifyOwnedAnchorEmpty(snapshot()),
                     PfAnchorCleanupVerification::NotEmpty);
            QCOMPARE(runner.calls.size(), 1);
            QCOMPARE(runner.calls.front().query, PfQuery::SessionFilterRules);
        }
        {
            FakePfCommandRunner runner;
            runner.outputs[1].standardOutput = "@0 rdr on en0 inet proto tcp\n";
            PfCommandAnchorCleanupVerifier verifier(runner);
            QCOMPARE(verifier.verifyOwnedAnchorEmpty(snapshot()),
                     PfAnchorCleanupVerification::NotEmpty);
            verifyCalls(runner, "llm_interceptor/cleanup-verifier-a",
                        PfCommandAnchorCleanupVerifier::defaultTimeoutMs);
        }
    }

    void failedCommandsAndNonzeroExitAreUnknownAndStop() {
        constexpr std::array<PfCommandStatus, 5> failures = {
            PfCommandStatus::PermissionDenied, PfCommandStatus::TimedOut,
            PfCommandStatus::OutputLimitExceeded, PfCommandStatus::Failed,
            PfCommandStatus::Completed};
        for (const auto status : failures) {
            FakePfCommandRunner runner;
            runner.outputs[0].status = status;
            runner.outputs[0].exitCode = status == PfCommandStatus::Completed ? 1 : 0;
            PfCommandAnchorCleanupVerifier verifier(runner);
            QCOMPARE(verifier.verifyOwnedAnchorEmpty(snapshot()),
                     PfAnchorCleanupVerification::Unknown);
            QCOMPARE(runner.calls.size(), 1);
            QCOMPARE(runner.calls.front().query, PfQuery::SessionFilterRules);
        }

        FakePfCommandRunner secondFailure;
        secondFailure.outputs[1].status = PfCommandStatus::TimedOut;
        PfCommandAnchorCleanupVerifier verifier(secondFailure, 1234);
        QCOMPARE(verifier.verifyOwnedAnchorEmpty(snapshot()), PfAnchorCleanupVerification::Unknown);
        QCOMPARE(secondFailure.calls.size(), 2);
        QCOMPARE(secondFailure.calls.back().query, PfQuery::SessionTranslationRules);
        verifyCalls(secondFailure, "llm_interceptor/cleanup-verifier-a", 1234);
    }

    void malformedOrOversizedOutputIsUnknown() {
        const QList<QByteArray> malformed = {
            "garbage\n", QByteArray("@0 pass in\n") + char(0xff),
            QByteArray("@0 pass in\n") + char(0x01),
            QByteArray(PfCommandAnchorCleanupVerifier::maximumOutputBytes + 1, ' ')};
        for (const auto &output : malformed) {
            FakePfCommandRunner runner;
            runner.outputs[0].standardOutput = output;
            PfCommandAnchorCleanupVerifier verifier(runner);
            QCOMPARE(verifier.verifyOwnedAnchorEmpty(snapshot()),
                     PfAnchorCleanupVerification::Unknown);
            QCOMPARE(runner.calls.size(), 1);
        }
    }

    void invalidTimeoutFailsClosedWithoutRunnerCalls() {
        for (const int timeout : {0, -1, PfDiagnostics::maximumTimeoutMs + 1}) {
            FakePfCommandRunner runner;
            PfCommandAnchorCleanupVerifier verifier(runner, timeout);
            QCOMPARE(verifier.verifyOwnedAnchorEmpty(snapshot()),
                     PfAnchorCleanupVerification::Unknown);
            QVERIFY(runner.calls.isEmpty());
        }
    }
};

QTEST_GUILESS_MAIN(M6PfAnchorCleanupVerifierTests)
#include "M6PfAnchorCleanupVerifierTests.moc"
