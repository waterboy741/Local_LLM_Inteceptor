#include "network/PfDiagnostics.hpp"

#include <QJsonDocument>
#include <QtTest>
#include <array>

using namespace interceptor;

class FakePfCommandRunner final : public PfCommandRunner {
  public:
    struct Call {
        PfQuery query;
        QString sessionAnchor;
        int timeoutMs;
        qsizetype outputLimitBytes;
    };

    QMap<int, PfQueryOutput> outputs;
    QVector<Call> calls;

    PfQueryOutput query(PfQuery requested, const QString &sessionAnchor, int timeoutMs,
                        qsizetype outputLimitBytes) override {
        calls.append({requested, sessionAnchor, timeoutMs, outputLimitBytes});
        const auto it = outputs.constFind(static_cast<int>(requested));
        return it == outputs.cend() ? PfQueryOutput{} : *it;
    }
};

class M6PfDiagnosticsTests : public QObject {
    Q_OBJECT

  private:
    static SessionConfig validConfig() {
        return {"en0", "192.0.2.10", "192.0.2.30", 18081, {"/api/generate"}, false};
    }

    static constexpr std::array<PfQuery, 7> expectedQueries = {PfQuery::Status,
                                                               PfQuery::MainFilterRules,
                                                               PfQuery::MainTranslationRules,
                                                               PfQuery::ApplicationAnchors,
                                                               PfQuery::SessionFilterRules,
                                                               PfQuery::SessionTranslationRules,
                                                               PfQuery::States};

    static QByteArray response(PfQuery query) {
        switch (query) {
        case PfQuery::Status:
            return "Status: Enabled\n";
        case PfQuery::MainFilterRules:
            return "@0 anchor \"llm_interceptor/*\" all\n";
        case PfQuery::MainTranslationRules:
            return "@0 rdr-anchor \"llm_interceptor/*\" all\n";
        case PfQuery::ApplicationAnchors:
            return "llm_interceptor/session-a\n";
        case PfQuery::SessionFilterRules:
            return "@0 pass in quick on en0 inet from 192.0.2.10 to 192.0.2.30 flags S/SA keep "
                   "state\n"
                   "Evaluations: 0 Packets: 23 Bytes: 1932\n";
        case PfQuery::SessionTranslationRules:
            return "@0 rdr on en0 inet proto tcp from 192.0.2.10 to 192.0.2.30 port = 18081 -> "
                   "127.0.0.1 port 11434\n";
        case PfQuery::States:
            return "all tcp 192.0.2.10:50623 -> 192.0.2.30:18081 ESTABLISHED:ESTABLISHED\n";
        }
        return {};
    }

    static FakePfCommandRunner successfulRunner() {
        FakePfCommandRunner runner;
        for (const auto query : expectedQueries)
            runner.outputs.insert(static_cast<int>(query),
                                  {PfCommandStatus::Completed, 0, response(query)});
        return runner;
    }

    static int indexOf(const QVector<FakePfCommandRunner::Call> &calls, PfQuery query) {
        for (qsizetype index = 0; index < calls.size(); ++index)
            if (calls[index].query == query)
                return static_cast<int>(index);
        return -1;
    }

  private slots:
    void successfulCollectionUsesOnlyBoundedReadOnlyQueries() {
        auto runner = successfulRunner();
        const auto config = validConfig();
        const auto result = PfDiagnostics::collect(config, "session-a", runner);

        QVERIFY(result.configValid);
        QVERIFY(result.complete);
        QVERIFY(result.pfEnabledKnown);
        QVERIFY(result.pfEnabled);
        QVERIFY(result.filterAttachmentKnown);
        QVERIFY(result.filterAttachmentReferenced);
        QVERIFY(result.translationAttachmentKnown);
        QVERIFY(result.translationAttachmentReferenced);
        QVERIFY(result.sessionAnchorKnown);
        QVERIFY(result.sessionAnchorLoaded);
        QVERIFY(result.sessionRulesKnown);
        QCOMPARE(result.sessionFilterRuleCount, 1);
        QCOMPARE(result.sessionTranslationRuleCount, 1);
        QVERIFY(result.filterCountersKnown);
        QVERIFY(result.filterCountersNonzero);
        QVERIFY(result.stateCandidatesKnown);
        QVERIFY(result.stateOutputRecognized);
        QCOMPARE(result.stateCandidateCount, 1);
        QVERIFY(!result.evaluationProven);

        QCOMPARE(runner.calls.size(), static_cast<qsizetype>(expectedQueries.size()));
        for (qsizetype i = 0; i < runner.calls.size(); ++i) {
            QCOMPARE(runner.calls[i].query, expectedQueries[static_cast<size_t>(i)]);
            QCOMPARE(runner.calls[i].sessionAnchor, QString("llm_interceptor/session-a"));
            QCOMPARE(runner.calls[i].timeoutMs, PfDiagnostics::defaultTimeoutMs);
            QCOMPARE(runner.calls[i].outputLimitBytes, PfDiagnostics::maximumOutputBytes);
        }
    }

    void invalidConfigSessionIdAndTimeoutMakeNoQueries() {
        {
            auto runner = successfulRunner();
            auto config = validConfig();
            config.serverPort = 65536;
            const auto result = PfDiagnostics::collect(config, "session-a", runner);
            QVERIFY(!result.complete);
            QVERIFY(!result.configValid);
            QVERIFY(!result.validationErrors.isEmpty());
            QVERIFY(runner.calls.isEmpty());
        }
        {
            auto runner = successfulRunner();
            const auto result = PfDiagnostics::collect(validConfig(), "../bad", runner);
            QVERIFY(!result.complete);
            QVERIFY(runner.calls.isEmpty());
        }
        for (const int timeoutMs : {0, -1, PfDiagnostics::maximumTimeoutMs + 1, 60000}) {
            auto runner = successfulRunner();
            const auto result =
                PfDiagnostics::collect(validConfig(), "session-a", runner, timeoutMs);
            QVERIFY(!result.complete);
            QVERIFY(runner.calls.isEmpty());
        }
    }

    void permissionDeniedStopsCollectionAndPreservesErrorCategory() {
        auto runner = successfulRunner();
        runner.outputs[static_cast<int>(PfQuery::MainTranslationRules)] = {
            PfCommandStatus::PermissionDenied, 1, "pfctl: Permission denied\n"};

        const auto result = PfDiagnostics::collect(validConfig(), "session-a", runner, 250);
        QVERIFY(!result.complete);
        QCOMPARE(runner.calls.size(), 3);
        QCOMPARE(runner.calls.last().query, PfQuery::MainTranslationRules);
        QCOMPARE(result.queries.size(), 7);
        QCOMPARE(result.queries[2].status, QString("permission_denied"));
        QCOMPARE(result.queries[3].status, QString("not_run"));
        QCOMPARE(result.timeoutMs, 250);
    }

    void timeoutOutputLimitAndExitFailuresFailClosed() {
        const QList<PfCommandStatus> failures = {PfCommandStatus::TimedOut,
                                                 PfCommandStatus::OutputLimitExceeded,
                                                 PfCommandStatus::Failed};
        for (const auto failure : failures) {
            auto runner = successfulRunner();
            runner.outputs[static_cast<int>(PfQuery::SessionFilterRules)] = {
                failure, -1, "sensitive-output-must-not-be-copied"};
            const auto result = PfDiagnostics::collect(validConfig(), "session-a", runner);
            QVERIFY(!result.complete);
            QVERIFY(!result.queries[4].status.isEmpty());
            QCOMPARE(result.queries[5].status, QString("not_run"));
            const auto json =
                QJsonDocument(result.toSanitizedJson()).toJson(QJsonDocument::Compact);
            QVERIFY(!json.contains("sensitive-output-must-not-be-copied"));
        }

        auto nonzeroRunner = successfulRunner();
        nonzeroRunner.outputs[static_cast<int>(PfQuery::Status)].exitCode = 1;
        const auto nonzero = PfDiagnostics::collect(validConfig(), "session-a", nonzeroRunner);
        QVERIFY(!nonzero.complete);
        QCOMPARE(nonzeroRunner.calls.size(), 1);
        QCOMPARE(nonzero.queries[0].status, QString("failed"));
    }

    void malformedAndUnrecognizedOutputNeverProducesCompleteEvidence() {
        for (const auto query : expectedQueries) {
            auto runner = successfulRunner();
            runner.outputs[static_cast<int>(query)].standardOutput =
                "unrecognized sensitive output 192.0.2.10\n";
            const auto result = PfDiagnostics::collect(validConfig(), "session-a", runner);
            QVERIFY(!result.complete);
            const int failedIndex = indexOf(runner.calls, query);
            QVERIFY(failedIndex >= 0);
            QCOMPARE(runner.calls.size(), failedIndex + 1);
            QVERIFY(!result.evaluationProven);
            const auto json =
                QJsonDocument(result.toSanitizedJson()).toJson(QJsonDocument::Compact);
            QVERIFY(!json.contains("unrecognized sensitive output"));
            QVERIFY(!json.contains("192.0.2.10"));
        }
    }

    void statesAreGlobalCandidatesAndDoNotClaimEvaluation() {
        auto runner = successfulRunner();
        runner.outputs[static_cast<int>(PfQuery::States)].standardOutput =
            "all tcp 192.0.2.99:50623 -> 192.0.2.30:18081 ESTABLISHED:ESTABLISHED\n"
            "all udp 192.0.2.10:50624 -> 192.0.2.30:18081 SINGLE:SINGLE\n";

        const auto result = PfDiagnostics::collect(validConfig(), "session-a", runner);
        QVERIFY(result.complete);
        QVERIFY(result.stateCandidatesKnown);
        QCOMPARE(result.stateCandidateCount, 1);
        QVERIFY(!result.evaluationProven);
    }

    void stateCandidateMatchingRequiresExactDirectionalClientAndServerEndpoints() {
        auto config = validConfig();
        config.clientIp = "192.0.2.1";
        config.serverPort = 1808;
        auto runner = successfulRunner();
        runner.outputs[static_cast<int>(PfQuery::States)].standardOutput =
            "all tcp 192.0.2.10:50100 -> 192.0.2.30:18081 ESTABLISHED:ESTABLISHED\n"
            "all tcp 192.0.2.1:50101 -> 192.0.2.30:18081 ESTABLISHED:ESTABLISHED\n"
            "all tcp 192.0.2.10:50102 -> 192.0.2.30:1808 ESTABLISHED:ESTABLISHED\n"
            "all tcp 192.0.2.1:50103 -> 192.0.2.30:1808 ESTABLISHED:ESTABLISHED\n"
            "all tcp 192.0.2.30:1808 -> 192.0.2.1:50104 ESTABLISHED:ESTABLISHED\n";

        const auto result = PfDiagnostics::collect(config, "session-a", runner);
        QVERIFY(result.complete);
        QVERIFY(result.stateCandidatesKnown);
        QCOMPARE(result.stateCandidateCount, 1);
        QVERIFY(!result.evaluationProven);
    }

    void nestedForeignAnchorDoesNotCountAsTheSessionAnchor() {
        auto runner = successfulRunner();
        runner.outputs[static_cast<int>(PfQuery::ApplicationAnchors)].standardOutput =
            "other/session-a\n";

        const auto result = PfDiagnostics::collect(validConfig(), "session-a", runner);
        QVERIFY(result.complete);
        QVERIFY(result.sessionAnchorKnown);
        QVERIFY(!result.sessionAnchorLoaded);
    }

    void sanitizedEvidenceContainsOnlyAggregatesAndCannotRepresentMutations() {
        auto runner = successfulRunner();
        const auto result = PfDiagnostics::collect(validConfig(), "session-a", runner);
        const auto json = QJsonDocument(result.toSanitizedJson()).toJson(QJsonDocument::Compact);
        QVERIFY(json.contains("\"evaluation_proven\":false"));
        QVERIFY(json.contains("\"sanitized\":true"));
        QVERIFY(!json.contains("192.0.2.10"));
        QVERIFY(!json.contains("192.0.2.30"));
        QVERIFY(!json.contains("session-a"));
        QVERIFY(!json.contains("pfctl"));
        QVERIFY(!json.contains("raw_output"));
        for (const auto &call : runner.calls) {
            QVERIFY(call.query == PfQuery::Status || call.query == PfQuery::MainFilterRules ||
                    call.query == PfQuery::MainTranslationRules ||
                    call.query == PfQuery::ApplicationAnchors ||
                    call.query == PfQuery::SessionFilterRules ||
                    call.query == PfQuery::SessionTranslationRules ||
                    call.query == PfQuery::States);
        }
    }
};

QTEST_GUILESS_MAIN(M6PfDiagnosticsTests)
#include "M6PfDiagnosticsTests.moc"
