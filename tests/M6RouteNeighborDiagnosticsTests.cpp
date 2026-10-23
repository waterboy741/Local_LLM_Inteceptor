#include "network/RouteNeighborDiagnostics.hpp"

#include <QJsonDocument>
#include <QMap>
#include <QtTest>
#include <array>

using namespace interceptor;

class FakeNetworkCommandRunner final : public NetworkCommandRunner {
  public:
    struct Call {
        NetworkQuery query;
        QString interfaceName;
        QString ipv4;
        int timeoutMs;
        qsizetype outputLimitBytes;
    };

    QMap<int, NetworkQueryOutput> outputs;
    QVector<Call> calls;

    NetworkQueryOutput query(NetworkQuery requested, const QString &interfaceName,
                             const QString &ipv4, int timeoutMs,
                             qsizetype outputLimitBytes) override {
        calls.append({requested, interfaceName, ipv4, timeoutMs, outputLimitBytes});
        const auto it = outputs.constFind(static_cast<int>(requested));
        return it == outputs.cend() ? NetworkQueryOutput{} : *it;
    }
};

class M6RouteNeighborDiagnosticsTests : public QObject {
    Q_OBJECT

  private:
    static SessionConfig validConfig() {
        return {"en0", "192.0.2.10", "192.0.2.30", 18081, {"/api/generate"}, false};
    }

    static constexpr std::array<NetworkQuery, 4> expectedQueries = {
        NetworkQuery::ClientRoute, NetworkQuery::ServerRoute, NetworkQuery::ClientNeighbor,
        NetworkQuery::ServerNeighbor};

    static QString addressFor(NetworkQuery query) {
        return query == NetworkQuery::ClientRoute || query == NetworkQuery::ClientNeighbor
                   ? "192.0.2.10"
                   : "192.0.2.30";
    }

    static QByteArray routeOutput(const QString &address, const QString &gateway,
                                  const QString &interface = "en0") {
        return QString("route to: %1\ndestination: 192.0.2.0\nmask: 255.255.255.0\n"
                       "gateway: %2\ninterface: %3\nflags: <UP,DONE,STATIC>\n")
            .arg(address, gateway, interface)
            .toUtf8();
    }

    static QByteArray neighborOutput(const QString &address, const QString &mac,
                                     const QString &interface = "en0") {
        return QString("? (%1) at %2 on %3 ifscope [ethernet]\n")
            .arg(address, mac, interface)
            .toUtf8();
    }

    static FakeNetworkCommandRunner successfulRunner() {
        FakeNetworkCommandRunner runner;
        runner.outputs.insert(
            static_cast<int>(NetworkQuery::ClientRoute),
            {NetworkCommandStatus::Completed, 0, routeOutput("192.0.2.10", "link#14")});
        runner.outputs.insert(
            static_cast<int>(NetworkQuery::ServerRoute),
            {NetworkCommandStatus::Completed, 0, routeOutput("192.0.2.30", "192.0.2.1")});
        runner.outputs.insert(static_cast<int>(NetworkQuery::ClientNeighbor),
                              {NetworkCommandStatus::Completed, 0,
                               neighborOutput("192.0.2.10", "02:00:00:00:00:10")});
        runner.outputs.insert(static_cast<int>(NetworkQuery::ServerNeighbor),
                              {NetworkCommandStatus::Completed, 0,
                               neighborOutput("192.0.2.30", "02:00:00:00:00:30")});
        return runner;
    }

  private slots:
    void successfulCollectionUsesFourBoundedReadOnlyQueries() {
        auto runner = successfulRunner();
        const auto result = RouteNeighborDiagnostics::collect(validConfig(), runner, 400);

        QVERIFY(result.configValid);
        QVERIFY(result.complete);
        QCOMPARE(result.statusCode, QString("observations_complete"));
        QVERIFY(result.client.routeRecognized);
        QVERIFY(result.client.routeInterfaceMatches);
        QVERIFY(result.client.routeDirect);
        QVERIFY(result.client.neighborRecognized);
        QVERIFY(result.client.neighborResolved);
        QVERIFY(result.client.neighborInterfaceMatches);
        QVERIFY(result.server.routeRecognized);
        QVERIFY(result.server.routeInterfaceMatches);
        QVERIFY(!result.server.routeDirect);
        QVERIFY(result.server.neighborRecognized);
        QVERIFY(result.server.neighborResolved);
        QVERIFY(result.server.neighborInterfaceMatches);

        QCOMPARE(runner.calls.size(), static_cast<qsizetype>(expectedQueries.size()));
        QCOMPARE(result.queries.size(), static_cast<qsizetype>(expectedQueries.size()));
        for (qsizetype i = 0; i < runner.calls.size(); ++i) {
            const auto &call = runner.calls[i];
            QCOMPARE(call.query, expectedQueries[static_cast<size_t>(i)]);
            QCOMPARE(call.interfaceName, QString("en0"));
            QCOMPARE(call.ipv4, addressFor(call.query));
            QCOMPARE(call.timeoutMs, 400);
            QCOMPARE(call.outputLimitBytes, RouteNeighborDiagnostics::maximumOutputBytes);
            QCOMPARE(result.queries[i].query, call.query);
            QCOMPARE(result.queries[i].status, QString("completed"));
        }
    }

    void wrongRouteOrNeighborInterfaceIsReportedAsMismatch() {
        auto runner = successfulRunner();
        runner.outputs[static_cast<int>(NetworkQuery::ClientRoute)].standardOutput =
            routeOutput("192.0.2.10", "link#14", "en1");
        runner.outputs[static_cast<int>(NetworkQuery::ServerNeighbor)].standardOutput =
            neighborOutput("192.0.2.30", "02:00:00:00:00:30", "en1");

        const auto result = RouteNeighborDiagnostics::collect(validConfig(), runner);
        QVERIFY(result.complete);
        QVERIFY(result.client.routeRecognized);
        QVERIFY(!result.client.routeInterfaceMatches);
        QVERIFY(result.server.neighborRecognized);
        QVERIFY(!result.server.neighborInterfaceMatches);
    }

    void directAndGatewayRoutesAreDistinguished() {
        auto runner = successfulRunner();
        runner.outputs[static_cast<int>(NetworkQuery::ClientRoute)].standardOutput =
            routeOutput("192.0.2.10", "192.0.2.1");
        runner.outputs[static_cast<int>(NetworkQuery::ServerRoute)].standardOutput =
            routeOutput("192.0.2.30", "link#14");

        const auto result = RouteNeighborDiagnostics::collect(validConfig(), runner);
        QVERIFY(result.complete);
        QVERIFY(!result.client.routeDirect);
        QVERIFY(result.server.routeDirect);
    }

    void routeWithLinkLayerFlagsAndNoGatewayIsRecognizedWithoutInferringDirectness() {
        auto runner = successfulRunner();
        runner.outputs[static_cast<int>(NetworkQuery::ClientRoute)].standardOutput =
            "route to: 192.0.2.10\ndestination: 192.0.2.10\nmask: 255.255.255.255\n"
            "interface: en0\nflags: <UP,HOST,LLINFO,WASCLONED,IFSCOPE>\n";

        const auto result = RouteNeighborDiagnostics::collect(validConfig(), runner);
        QVERIFY(result.complete);
        QVERIFY(result.client.routeRecognized);
        QVERIFY(result.client.routeInterfaceMatches);
        QVERIFY(!result.client.routeDirectKnown);
        QVERIFY(!result.client.routeDirect);
    }

    void malformedGatewayValuesAreNotAcceptedAsRoutes() {
        for (const auto &gateway : {QString("link#garbage"), QString("300.0.0.1")}) {
            auto runner = successfulRunner();
            runner.outputs[static_cast<int>(NetworkQuery::ClientRoute)].standardOutput =
                routeOutput("192.0.2.10", gateway);
            const auto result = RouteNeighborDiagnostics::collect(validConfig(), runner);
            QVERIFY(!result.complete);
            QVERIFY(!result.client.routeRecognized);
            QVERIFY(!result.client.routeDirectKnown);
        }
    }

    void unresolvedMacEntryIsRecognizedButNotResolved() {
        auto runner = successfulRunner();
        runner.outputs[static_cast<int>(NetworkQuery::ServerNeighbor)].standardOutput =
            "? (192.0.2.30) at (incomplete) on en0\n";

        const auto result = RouteNeighborDiagnostics::collect(validConfig(), runner);
        QVERIFY(result.complete);
        QVERIFY(result.server.neighborRecognized);
        QVERIFY(!result.server.neighborResolved);
        QVERIFY(result.server.neighborInterfaceMatches);
    }

    void arpNoEntryDiagnosticIsARecognizedUnresolvedObservation() {
        const QList<QPair<NetworkQueryOutput, bool>> cases = {
            {{NetworkCommandStatus::NoEntry, 1, {}, "192.0.2.10 (192.0.2.10) -- no entry\n"},
             false},
            {{NetworkCommandStatus::NoEntry, 0, "192.0.2.10 (192.0.2.10) -- no entry on en0\n", {}},
             true},
        };
        for (const auto &[output, interfaceMatches] : cases) {
            auto runner = successfulRunner();
            runner.outputs[static_cast<int>(NetworkQuery::ClientNeighbor)] = output;

            const auto result = RouteNeighborDiagnostics::collect(validConfig(), runner);
            QVERIFY(result.complete);
            QVERIFY(result.client.neighborRecognized);
            QVERIFY(!result.client.neighborResolved);
            QCOMPARE(result.client.neighborInterfaceMatches, interfaceMatches);
            QCOMPARE(result.queries[2].status, QString("no_entry"));
        }
    }

    void explicitProxyWithoutAnInterfaceIsRejectedBeforeQueries() {
        auto runner = successfulRunner();
        SessionConfig config{"", "127.0.0.1", "127.0.0.2", 18081, {"/api/generate"}, true};
        QVERIFY(config.validate().isEmpty());

        const auto result = RouteNeighborDiagnostics::collect(config, runner);
        QVERIFY(!result.configValid);
        QVERIFY(!result.complete);
        QVERIFY(!result.validationErrors.isEmpty());
        QVERIFY(runner.calls.isEmpty());
    }

    void missingAndMalformedRouteOrNeighborEvidenceFailsClosed() {
        for (const auto query : {NetworkQuery::ClientRoute, NetworkQuery::ServerRoute,
                                 NetworkQuery::ClientNeighbor, NetworkQuery::ServerNeighbor}) {
            auto runner = successfulRunner();
            runner.outputs[static_cast<int>(query)].standardOutput =
                "unrecognized output for 192.0.2.10 from /sbin/route and /usr/sbin/arp\n";
            const auto result = RouteNeighborDiagnostics::collect(validConfig(), runner);
            QVERIFY(!result.complete);
            QCOMPARE(runner.calls.size(), static_cast<qsizetype>(expectedQueries.size()));
            QCOMPARE(result.queries.size(), static_cast<qsizetype>(expectedQueries.size()));
        }

        auto missingRoute = successfulRunner();
        missingRoute.outputs[static_cast<int>(NetworkQuery::ClientRoute)] = {
            NetworkCommandStatus::Failed, 1, {}, "route: no route to host 192.0.2.10"};
        const auto result = RouteNeighborDiagnostics::collect(validConfig(), missingRoute);
        QVERIFY(!result.complete);
        QCOMPARE(missingRoute.calls.size(), static_cast<qsizetype>(expectedQueries.size()));
        QCOMPARE(result.queries[0].status, QString("failed"));
        QCOMPARE(result.queries[3].status, QString("completed"));
    }

    void permissionTimeoutAndOutputLimitFailuresContinueWithRemainingQueries() {
        const QList<QPair<NetworkCommandStatus, QString>> failures = {
            {NetworkCommandStatus::PermissionDenied, "permission_denied"},
            {NetworkCommandStatus::TimedOut, "timed_out"},
            {NetworkCommandStatus::OutputLimitExceeded, "output_limit_exceeded"}};
        for (const auto &[failure, expectedStatus] : failures) {
            auto runner = successfulRunner();
            runner.outputs[static_cast<int>(NetworkQuery::ServerRoute)] = {
                failure, -1, "sensitive 198.51.100.7 02:00:00:00:00:07 /sbin/route"};
            const auto result = RouteNeighborDiagnostics::collect(validConfig(), runner, 250);
            QVERIFY(!result.complete);
            QCOMPARE(runner.calls.size(), static_cast<qsizetype>(expectedQueries.size()));
            QCOMPARE(result.queries[1].status, expectedStatus);
            QCOMPARE(result.queries[2].status, QString("completed"));
            QCOMPARE(result.timeoutMs, 250);
            const auto json =
                QJsonDocument(result.toSanitizedJson()).toJson(QJsonDocument::Compact);
            QVERIFY(!json.contains("sensitive"));
            QVERIFY(!json.contains("198.51.100.7"));
            QVERIFY(!json.contains("02:00:00:00:00:07"));
            QVERIFY(!json.contains("/sbin/route"));
        }
    }

    void invalidConfigAndTimeoutMakeNoQueries() {
        {
            auto runner = successfulRunner();
            auto config = validConfig();
            config.serverPort = 65536;
            const auto result = RouteNeighborDiagnostics::collect(config, runner);
            QVERIFY(!result.configValid);
            QVERIFY(!result.complete);
            QVERIFY(!result.validationErrors.isEmpty());
            QVERIFY(runner.calls.isEmpty());
        }
        for (const int timeoutMs : {0, -1, RouteNeighborDiagnostics::maximumTimeoutMs + 1, 60000}) {
            auto runner = successfulRunner();
            const auto result = RouteNeighborDiagnostics::collect(validConfig(), runner, timeoutMs);
            QVERIFY(!result.complete);
            QCOMPARE(result.statusCode, QString("invalid_timeout"));
            QVERIFY(runner.calls.isEmpty());
        }
    }

    void sanitizedEvidenceOmitsAddressesMacsGatewaysAndCommandPaths() {
        auto runner = successfulRunner();
        const auto result = RouteNeighborDiagnostics::collect(validConfig(), runner);
        const auto json = QJsonDocument(result.toSanitizedJson()).toJson(QJsonDocument::Compact);
        QVERIFY(json.contains("\"sanitized\":true"));
        QVERIFY(json.contains("\"packet_egress_proven\":false"));
        QVERIFY(json.contains("\"layer2_or_arp_acceptance_proven\":false"));
        QVERIFY(json.contains("\"redirection_proven\":false"));
        for (const auto &sensitive :
             {"192.0.2.10", "192.0.2.30", "192.0.2.1", "02:00:00:00:00:10", "02:00:00:00:00:30",
              "link#14", "/sbin/route", "/usr/sbin/arp", "raw_output"})
            QVERIFY(!json.contains(sensitive));
        for (const auto &call : runner.calls)
            QVERIFY(call.query == NetworkQuery::ClientRoute ||
                    call.query == NetworkQuery::ServerRoute ||
                    call.query == NetworkQuery::ClientNeighbor ||
                    call.query == NetworkQuery::ServerNeighbor);
    }
};

QTEST_GUILESS_MAIN(M6RouteNeighborDiagnosticsTests)
#include "M6RouteNeighborDiagnosticsTests.moc"
