#include "network/PfAnchorOperations.hpp"

#include <QtTest>

using namespace interceptor;

class FakePfAnchorAuthorization final : public PfAnchorAuthorization {
  public:
    bool root = true;
    bool enabled = true;
    bool leaseValid = true;
    bool attachmentValid = true;
    bool ownershipValid = true;
    QStringList calls;
    QString observedLease;
    QString ownedAnchor;
    PfAnchorOperation ownedOperation = PfAnchorOperation::Install;

    bool effectiveUserIsRoot() override {
        calls << "root";
        return root;
    }
    bool pfEnabled() override {
        calls << "pf-enabled";
        return enabled;
    }
    bool verifySessionLease(const SessionSnapshot &, const QString &leaseToken) override {
        calls << "lease";
        observedLease = leaseToken;
        return leaseValid;
    }
    bool verifyActiveAttachment(const SessionSnapshot &) override {
        calls << "attachment";
        return attachmentValid;
    }
    bool verifyAnchorOwnership(const SessionSnapshot &snapshot, const QString &leaseToken,
                               PfAnchorOperation operation) override {
        calls << "ownership";
        observedLease = leaseToken;
        ownedAnchor = snapshot.anchor();
        ownedOperation = operation;
        return ownershipValid;
    }
};

class FakePfAnchorCommandRunner final : public PfAnchorCommandRunner {
  public:
    struct Call {
        QString program;
        QStringList arguments;
        QByteArray standardInput;
        int timeoutMs = 0;
        qsizetype outputLimitBytes = 0;
        PfAnchorOperation operation = PfAnchorOperation::Install;
        QString anchor;
    };

    PfAnchorCommandResult nextResult{PfAnchorCommandStatus::Completed, 0, true, true};
    QVector<Call> calls;

    PfAnchorCommandResult execute(const PfAnchorCommand &command, int timeoutMs,
                                  qsizetype outputLimitBytes) override {
        calls.append({command.program(), command.arguments(), command.standardInput(), timeoutMs,
                      outputLimitBytes, command.operation(), command.anchor()});
        return nextResult;
    }
};

class M6PfAnchorOperationsTests : public QObject {
    Q_OBJECT

  private:
    static SessionConfig validConfig() {
        return {"en0", "192.0.2.10", "192.0.2.30", 18081, {"/api/generate"}, false};
    }

    static NetworkFacts validFacts() {
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
        return facts;
    }

    static std::optional<SessionSnapshot> snapshot(const QString &sessionId = "test-session") {
        return SessionSnapshot::create(validConfig(), validFacts(), 11434, sessionId);
    }

    static QStringList successfulAuthorizationCalls() {
        return {"root", "lease", "pf-enabled", "attachment", "ownership"};
    }

  private slots:
    void installUsesExactOwnedAnchorCommandAndRulesInput() {
        const auto session = snapshot();
        QVERIFY(session.has_value());
        FakePfAnchorAuthorization authorization;
        FakePfAnchorCommandRunner runner;
        PfAnchorOperations operations(authorization, runner);

        const auto result = operations.install(*session, "lease-token-1");

        QVERIFY(result.success);
        QVERIFY(result.mayHaveApplied);
        QCOMPARE(result.statusCode, QString("completed"));
        QCOMPARE(authorization.calls, successfulAuthorizationCalls());
        QCOMPARE(authorization.observedLease, QString("lease-token-1"));
        QCOMPARE(authorization.ownedAnchor, QString("llm_interceptor/test-session"));
        QCOMPARE(authorization.ownedOperation, PfAnchorOperation::Install);
        QCOMPARE(runner.calls.size(), 1);
        const auto &call = runner.calls.first();
        QCOMPARE(call.program, QString("/sbin/pfctl"));
        QCOMPARE(call.arguments, (QStringList{"-a", "llm_interceptor/test-session", "-f", "-"}));
        QCOMPARE(call.operation, PfAnchorOperation::Install);
        QCOMPARE(call.anchor, QString("llm_interceptor/test-session"));
        QCOMPARE(call.standardInput, session->pfRules().toUtf8());
        QCOMPARE(call.timeoutMs, PfAnchorOperations::commandTimeoutMs);
        QCOMPARE(call.outputLimitBytes, PfAnchorOperations::maximumOutputBytes);
        QVERIFY(!call.arguments.contains("-F"));
        QVERIFY(!call.arguments.contains("-X"));
    }

    void cleanupRemovesOnlyRulesInTheOwnedAnchorAndRetainsTheLease() {
        const auto session = snapshot();
        QVERIFY(session.has_value());
        FakePfAnchorAuthorization authorization;
        FakePfAnchorCommandRunner runner;
        PfAnchorOperations operations(authorization, runner);

        const auto result = operations.remove(*session, "lease-token-2");

        QVERIFY(result.success);
        QVERIFY(result.mayHaveApplied);
        QCOMPARE(authorization.calls, (QStringList{"root", "lease", "ownership"}));
        QCOMPARE(authorization.observedLease, QString("lease-token-2"));
        QCOMPARE(authorization.ownedOperation, PfAnchorOperation::RemoveRules);
        QCOMPARE(runner.calls.size(), 1);
        const auto &call = runner.calls.first();
        QCOMPARE(call.program, QString("/sbin/pfctl"));
        QCOMPARE(call.arguments,
                 (QStringList{"-a", "llm_interceptor/test-session", "-F", "rules"}));
        QCOMPARE(call.operation, PfAnchorOperation::RemoveRules);
        QVERIFY(call.standardInput.isEmpty());
        QVERIFY(!call.arguments.contains("states"));
        QVERIFY(!call.arguments.contains("-X"));
        QVERIFY(!call.arguments.contains("-d"));
        QVERIFY(!call.arguments.contains("-e"));
    }

    void cleanupCanRemoveOwnedRulesAfterPfOrAttachmentBecomesUnavailable() {
        const auto session = snapshot();
        QVERIFY(session.has_value());
        for (const auto [pfEnabled, attachmentValid] :
             {QPair{false, true}, QPair{true, false}, QPair{false, false}}) {
            FakePfAnchorAuthorization authorization;
            authorization.enabled = pfEnabled;
            authorization.attachmentValid = attachmentValid;
            FakePfAnchorCommandRunner runner;
            PfAnchorOperations operations(authorization, runner);

            const auto result = operations.remove(*session, "lease-token-cleanup");

            QVERIFY(result.success);
            QVERIFY(result.mayHaveApplied);
            QCOMPARE(authorization.calls, (QStringList{"root", "lease", "ownership"}));
            QCOMPARE(authorization.observedLease, QString("lease-token-cleanup"));
            QCOMPARE(authorization.ownedOperation, PfAnchorOperation::RemoveRules);
            QCOMPARE(runner.calls.size(), 1);
            QCOMPARE(runner.calls.first().arguments,
                     (QStringList{"-a", "llm_interceptor/test-session", "-F", "rules"}));
        }
    }

    void cleanupStillRequiresRootCurrentLeaseAndAnchorOwnership() {
        const auto session = snapshot();
        QVERIFY(session.has_value());
        struct GateCase {
            bool root;
            bool leaseValid;
            bool ownershipValid;
            QString expectedStatus;
            QStringList expectedCalls;
        };
        const QList<GateCase> cases = {
            {false, true, true, "root_required", {"root"}},
            {true, false, true, "session_lease_unverified", {"root", "lease"}},
            {true, true, false, "anchor_ownership_unverified", {"root", "lease", "ownership"}},
        };
        for (const auto &test : cases) {
            FakePfAnchorAuthorization authorization;
            authorization.root = test.root;
            authorization.leaseValid = test.leaseValid;
            authorization.ownershipValid = test.ownershipValid;
            FakePfAnchorCommandRunner runner;
            PfAnchorOperations operations(authorization, runner);

            const auto result = operations.remove(*session, "lease-token");

            QVERIFY(!result.success);
            QVERIFY(!result.mayHaveApplied);
            QCOMPARE(result.statusCode, test.expectedStatus);
            QCOMPARE(authorization.calls, test.expectedCalls);
            QVERIFY(runner.calls.isEmpty());
        }
    }

    void nonRootCallerCannotRunPfCommands() {
        const auto session = snapshot();
        QVERIFY(session.has_value());
        FakePfAnchorAuthorization authorization;
        authorization.root = false;
        FakePfAnchorCommandRunner runner;
        PfAnchorOperations operations(authorization, runner);

        const auto result = operations.install(*session, "lease-token");

        QVERIFY(!result.success);
        QVERIFY(!result.mayHaveApplied);
        QCOMPARE(result.statusCode, QString("root_required"));
        QCOMPARE(authorization.calls, QStringList{"root"});
        QVERIFY(runner.calls.isEmpty());
    }

    void leasePfStateAttachmentAndOwnershipGateCommandsInOrder() {
        const auto session = snapshot();
        QVERIFY(session.has_value());
        struct GateCase {
            bool leaseValid;
            bool pfEnabled;
            bool attachmentValid;
            bool ownershipValid;
            QString expectedStatus;
            QStringList expectedCalls;
        };
        const QList<GateCase> cases = {
            {false, true, true, true, "session_lease_unverified", {"root", "lease"}},
            {true, false, true, true, "pf_disabled_or_unknown", {"root", "lease", "pf-enabled"}},
            {true,
             true,
             false,
             true,
             "active_attachment_unverified",
             {"root", "lease", "pf-enabled", "attachment"}},
            {true,
             true,
             true,
             false,
             "anchor_ownership_unverified",
             {"root", "lease", "pf-enabled", "attachment", "ownership"}},
        };
        for (const auto &test : cases) {
            FakePfAnchorAuthorization authorization;
            authorization.leaseValid = test.leaseValid;
            authorization.enabled = test.pfEnabled;
            authorization.attachmentValid = test.attachmentValid;
            authorization.ownershipValid = test.ownershipValid;
            FakePfAnchorCommandRunner runner;
            PfAnchorOperations operations(authorization, runner);

            const auto result = operations.install(*session, "lease-token");

            QVERIFY(!result.success);
            QVERIFY(!result.mayHaveApplied);
            QCOMPARE(result.statusCode, test.expectedStatus);
            QCOMPARE(authorization.calls, test.expectedCalls);
            QVERIFY(runner.calls.isEmpty());
        }
    }

    void invalidOrStaleLeaseTokensAreRejectedBeforeAnchorOwnershipCheck() {
        const auto session = snapshot();
        QVERIFY(session.has_value());
        for (const auto &lease : {QString{}, QString("bad token")}) {
            FakePfAnchorAuthorization authorization;
            FakePfAnchorCommandRunner runner;
            PfAnchorOperations operations(authorization, runner);

            const auto result = operations.remove(*session, lease);

            QVERIFY(!result.success);
            QVERIFY(!result.mayHaveApplied);
            QCOMPARE(result.statusCode, QString("session_lease_unverified"));
            QCOMPARE(authorization.calls, QStringList{"root"});
            QVERIFY(runner.calls.isEmpty());
        }
        QVERIFY(!snapshot("../foreign\nanchor").has_value());
    }

    void failedOrPartialCommandsPreserveConservativeMayHaveAppliedState() {
        const auto session = snapshot();
        QVERIFY(session.has_value());
        const QList<QPair<PfAnchorCommandResult, QString>> cases = {
            {{PfAnchorCommandStatus::PermissionDenied, 1, true, true}, "permission_denied"},
            {{PfAnchorCommandStatus::TimedOut, -1, true, true}, "timed_out"},
            {{PfAnchorCommandStatus::OutputLimitExceeded, -1, true, true}, "output_limit_exceeded"},
            {{PfAnchorCommandStatus::Failed, 2, true, true}, "command_failed"},
            {{PfAnchorCommandStatus::Completed, 0, false, false}, "command_not_started"},
            {{PfAnchorCommandStatus::Completed, 1, true, true}, "nonzero_exit"},
            {{PfAnchorCommandStatus::Completed, 0, true, false}, "process_unreaped"},
        };
        for (const auto &[commandResult, expectedStatus] : cases) {
            for (const bool install : {true, false}) {
                FakePfAnchorAuthorization authorization;
                FakePfAnchorCommandRunner runner;
                runner.nextResult = commandResult;
                PfAnchorOperations operations(authorization, runner);

                const auto result = install ? operations.install(*session, "lease-token")
                                            : operations.remove(*session, "lease-token");

                QVERIFY(!result.success);
                QCOMPARE(result.mayHaveApplied, commandResult.started);
                QCOMPARE(result.statusCode, expectedStatus);
                QCOMPARE(runner.calls.size(), 1);
                QCOMPARE(runner.calls.first().operation,
                         install ? PfAnchorOperation::Install : PfAnchorOperation::RemoveRules);
            }
        }
    }

    void commandAndOperationResultsDoNotExposeRunnerOutputOrMachineState() {
        const auto session = snapshot();
        QVERIFY(session.has_value());
        FakePfAnchorAuthorization authorization;
        FakePfAnchorCommandRunner runner;
        runner.nextResult = {PfAnchorCommandStatus::Failed, 1, true, true};
        PfAnchorOperations operations(authorization, runner);

        const auto result = operations.install(*session, "lease-token");

        QVERIFY(!result.success);
        QCOMPARE(result.statusCode, QString("command_failed"));
        const auto text = result.statusCode + authorization.calls.join(',');
        QVERIFY(!text.contains("/sbin/pfctl"));
        QVERIFY(!text.contains("192.0.2."));
        QVERIFY(!text.contains("llm_interceptor/test-session"));
        QVERIFY(!text.contains("raw_output"));
        QCOMPARE(runner.calls.size(), 1);
    }
};

QTEST_GUILESS_MAIN(M6PfAnchorOperationsTests)
#include "M6PfAnchorOperationsTests.moc"
