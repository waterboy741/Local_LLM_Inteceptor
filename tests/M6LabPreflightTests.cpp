#include "core/SessionConfig.hpp"
#include "network/LabPreflight.hpp"

#include <QJsonDocument>
#include <QtTest>

using namespace interceptor;

class FakeLabProbe final : public LabProbe {
  public:
    bool exists = true;
    bool up = true;
    QStringList addresses{"192.0.2.20"};
    TcpProbeResult tcpResult = TcpProbeResult::Reachable;
    QStringList calls;
    QStringList probedInterfaces;
    QString connectedInterface;
    QString connectedServer;
    int connectedPort = 0;
    int connectedTimeoutMs = 0;

    bool interfaceExists(const QString &name) override {
        calls << "interfaceExists";
        probedInterfaces << name;
        return exists;
    }
    bool interfaceUp(const QString &name) override {
        calls << "interfaceUp";
        probedInterfaces << name;
        return up;
    }
    QStringList interfaceIPv4Addresses(const QString &name) override {
        calls << "interfaceIPv4Addresses";
        probedInterfaces << name;
        return addresses;
    }
    TcpProbeResult connectTcp(const QString &interfaceName, const QString &serverIp, int serverPort,
                              int timeoutMs) override {
        calls << "connectTcp";
        connectedInterface = interfaceName;
        connectedServer = serverIp;
        connectedPort = serverPort;
        connectedTimeoutMs = timeoutMs;
        return tcpResult;
    }
};

class M6LabPreflightTests : public QObject {
    Q_OBJECT

  private:
    static SessionConfig validConfig() {
        return {"synthetic0", "192.0.2.10", "192.0.2.30", 18081, {"/api/generate"}, false};
    }

  private slots:
    void invalidTargetsAreRejectedBeforeAnyProbe() {
        const QList<SessionConfig> invalidConfigs = {
            {"synthetic0", "192.0.2.10", "192.0.2.30", 0, {"/api/generate"}, false},
            {"synthetic0", "192.0.2.10", "192.0.2.10", 18081, {"/api/generate"}, false},
            {"synthetic0", "192.0.2.10", "224.0.0.1", 18081, {"/api/generate"}, false},
            {"synthetic0", "192.0.2.10", "192.0.2.30", 18081, {"api/generate"}, false},
        };
        for (const auto &config : invalidConfigs) {
            FakeLabProbe probe;
            const auto result = LabPreflight::run(config, probe);
            QVERIFY(!result.configValid);
            QVERIFY(!result.complete);
            QCOMPARE(result.statusCode, QString("invalid_config"));
            QVERIFY(!result.validationErrors.isEmpty());
            QVERIFY2(probe.calls.isEmpty(),
                     "Invalid targets must not trigger even a read-only probe");
        }
    }

    void timeoutMustBeWithinBoundBeforeAnyProbe() {
        for (const int timeoutMs : {0, -1, LabPreflight::maximumTimeoutMs + 1, 60000}) {
            FakeLabProbe probe;
            const auto result = LabPreflight::run(validConfig(), probe, timeoutMs);
            QVERIFY(!result.complete);
            QCOMPARE(result.statusCode, QString("invalid_timeout"));
            QVERIFY(!result.validationErrors.isEmpty());
            QVERIFY(probe.calls.isEmpty());
        }
    }

    void eachLocalReadinessFailureStopsBeforeTcpProbe() {
        {
            FakeLabProbe probe;
            probe.exists = false;
            const auto result = LabPreflight::run(validConfig(), probe);
            QCOMPARE(result.statusCode, QString("interface_missing"));
            QCOMPARE(probe.calls, QStringList{"interfaceExists"});
        }
        {
            FakeLabProbe probe;
            probe.up = false;
            const auto result = LabPreflight::run(validConfig(), probe);
            QCOMPARE(result.statusCode, QString("interface_down"));
            QCOMPARE(probe.calls, (QStringList{"interfaceExists", "interfaceUp"}));
        }
        {
            FakeLabProbe probe;
            probe.addresses.clear();
            const auto result = LabPreflight::run(validConfig(), probe);
            QCOMPARE(result.statusCode, QString("interface_no_ipv4"));
            QCOMPARE(result.interfaceHasUsableIPv4, false);
            QCOMPARE(probe.calls,
                     (QStringList{"interfaceExists", "interfaceUp", "interfaceIPv4Addresses"}));
        }
    }

    void tcpProbeUsesSelectedTargetAndBoundedTimeout() {
        FakeLabProbe probe;
        const auto config = validConfig();
        constexpr int timeoutMs = LabPreflight::maximumTimeoutMs;
        const auto result = LabPreflight::run(config, probe, timeoutMs);

        QVERIFY(result.configValid);
        QVERIFY(result.interfaceFound);
        QVERIFY(result.interfaceUp);
        QVERIFY(result.interfaceHasUsableIPv4);
        QVERIFY(result.serverTcpReachable);
        QVERIFY(result.complete);
        QCOMPARE(result.timeoutMs, timeoutMs);
        QCOMPARE(result.statusCode, QString("tcp_reachable"));
        QCOMPARE(probe.calls, (QStringList{"interfaceExists", "interfaceUp",
                                           "interfaceIPv4Addresses", "connectTcp"}));
        QCOMPARE(probe.connectedInterface, config.interfaceName);
        QCOMPARE(probe.connectedServer, config.serverIp);
        QCOMPARE(probe.connectedPort, config.serverPort);
        QCOMPARE(probe.connectedTimeoutMs, timeoutMs);
        QCOMPARE(probe.probedInterfaces,
                 (QStringList{config.interfaceName, config.interfaceName, config.interfaceName}));
    }

    void tcpFailuresAreReportedWithoutStartingSessionOperations() {
        const QList<QPair<TcpProbeResult, QString>> cases = {
            {TcpProbeResult::Refused, "tcp_refused"},
            {TcpProbeResult::TimedOut, "tcp_timed_out"},
            {TcpProbeResult::Error, "tcp_error"},
        };
        for (const auto &[tcpResult, expectedCode] : cases) {
            FakeLabProbe probe;
            probe.tcpResult = tcpResult;
            const auto result = LabPreflight::run(validConfig(), probe, 125);
            QVERIFY(result.configValid);
            QVERIFY(!result.serverTcpReachable);
            QVERIFY(!result.complete);
            QCOMPARE(result.statusCode, expectedCode);
            QCOMPARE(result.tcpStatus, expectedCode.mid(4));
            QCOMPARE(probe.connectedTimeoutMs, 125);
            QCOMPARE(probe.calls.size(), 4);
            QCOMPARE(probe.calls.last(), QString("connectTcp"));
        }
    }

    void sanitizedEvidenceOmitsLocalInterfaceAddressAndContainsNoMutationResult() {
        FakeLabProbe probe;
        probe.addresses = {"198.51.100.20", "2001:db8::20"};
        const auto config = validConfig();
        const auto document = QJsonDocument(LabPreflight::run(config, probe).toSanitizedJson());
        const auto json = document.toJson(QJsonDocument::Compact);
        QVERIFY(!json.contains("198.51.100.20"));
        QVERIFY(!json.contains("2001:db8::20"));
        QVERIFY(!json.contains(config.clientIp.toUtf8()));
        QVERIFY(!json.contains(config.serverIp.toUtf8()));
        QVERIFY(json.contains("\"sanitized\":true"));
        QVERIFY(!json.contains("arp"));
        QVERIFY(!json.contains("pf"));
        QVERIFY(!json.contains("forwarding"));
        QCOMPARE(probe.calls.size(), 4);
    }
};

QTEST_GUILESS_MAIN(M6LabPreflightTests)
#include "M6LabPreflightTests.moc"
