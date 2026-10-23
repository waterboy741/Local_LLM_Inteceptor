#include "core/SessionConfig.hpp"
#include "network/LabPreflight.hpp"

#include <QJsonDocument>
#include <QtTest>

using namespace interceptor;

class FakeLabProbe final : public LabProbe {
  public:
    InterfaceFacts facts{true, true, "02:00:00:00:00:20", {{"192.0.2.20", 24}}};
    TcpProbeResult tcpResult = TcpProbeResult::Reachable;
    QStringList calls;
    QString factsInterface;
    QString connectedInterface;
    QString connectedSource;
    QString connectedServer;
    int connectedPort = 0;
    int connectedTimeoutMs = 0;

    InterfaceFacts interfaceFacts(const QString &name) override {
        calls << "interfaceFacts";
        factsInterface = name;
        return facts;
    }
    TcpProbeResult connectTcp(const QString &interfaceName, const QString &sourceIpv4,
                              const QString &serverIp, int serverPort, int timeoutMs) override {
        calls << "connectTcp";
        connectedInterface = interfaceName;
        connectedSource = sourceIpv4;
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
            {"synthetic0", "192.0.2.10", "240.0.0.1", 18081, {"/api/generate"}, false},
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
            probe.facts.found = false;
            const auto result = LabPreflight::run(validConfig(), probe);
            QCOMPARE(result.statusCode, QString("interface_missing"));
            QCOMPARE(probe.calls, QStringList{"interfaceFacts"});
        }
        {
            FakeLabProbe probe;
            probe.facts.up = false;
            const auto result = LabPreflight::run(validConfig(), probe);
            QCOMPARE(result.statusCode, QString("interface_down"));
            QCOMPARE(probe.calls, QStringList{"interfaceFacts"});
        }
        {
            FakeLabProbe probe;
            probe.facts.ipv4Addresses.clear();
            const auto result = LabPreflight::run(validConfig(), probe);
            QCOMPARE(result.statusCode, QString("interface_no_ipv4"));
            QCOMPARE(result.interfaceHasUsableIPv4, false);
            QCOMPARE(probe.calls, QStringList{"interfaceFacts"});
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
        QVERIFY(result.interfaceHasValidMac);
        QVERIFY(result.clientOnSelectedSubnet);
        QVERIFY(result.serverOnSelectedSubnet);
        QVERIFY(result.sourceAddressSelected);
        QVERIFY(result.serverTcpReachable);
        QVERIFY(result.complete);
        QCOMPARE(result.timeoutMs, timeoutMs);
        QCOMPARE(result.statusCode, QString("tcp_reachable"));
        QCOMPARE(probe.calls, (QStringList{"interfaceFacts", "connectTcp"}));
        QCOMPARE(probe.factsInterface, config.interfaceName);
        QCOMPARE(probe.connectedInterface, config.interfaceName);
        QCOMPARE(probe.connectedSource, QString("192.0.2.20"));
        QCOMPARE(probe.connectedServer, config.serverIp);
        QCOMPARE(probe.connectedPort, config.serverPort);
        QCOMPARE(probe.connectedTimeoutMs, timeoutMs);
    }

    void equalSubnetDoesNotClaimLayerTwoOrArpCompatibility() {
        FakeLabProbe probe;
        const auto result = LabPreflight::run(validConfig(), probe);
        QVERIFY(result.clientOnSelectedSubnet);
        QVERIFY(result.serverOnSelectedSubnet);
        const auto json = QJsonDocument(result.toSanitizedJson()).toJson(QJsonDocument::Compact);
        QVERIFY(json.contains("\"client_on_selected_subnet\":true"));
        QVERIFY(json.contains("\"server_on_selected_subnet\":true"));
        QVERIFY(!json.contains("\"arp_compatible\":true"));
        QVERIFY(!json.contains("\"layer2_compatible\":true"));
        QVERIFY(!json.contains("\"arp_proven\":true"));
    }

    void peerOutsideSelectedSubnetFailsBeforeTcpProbe() {
        FakeLabProbe probe;
        probe.facts.ipv4Addresses = {{"192.0.2.20", 24}};
        const SessionConfig config{"synthetic0", "198.51.100.10",   "192.0.2.30",
                                   18081,        {"/api/generate"}, false};
        const auto result = LabPreflight::run(config, probe);
        QVERIFY(!result.complete);
        QCOMPARE(result.statusCode, QString("no_common_subnet"));
        QVERIFY(!result.clientOnSelectedSubnet);
        QVERIFY(result.serverOnSelectedSubnet);
        QCOMPARE(probe.calls, QStringList{"interfaceFacts"});
    }

    void peersOnDifferentInterfaceSubnetsDoNotPassPreflight() {
        FakeLabProbe probe;
        probe.facts.ipv4Addresses = {{"192.0.2.20", 24}, {"198.51.100.20", 24}};
        const SessionConfig config{"synthetic0", "192.0.2.10",      "198.51.100.30",
                                   18081,        {"/api/generate"}, false};
        const auto result = LabPreflight::run(config, probe);
        QVERIFY(!result.complete);
        QCOMPARE(result.statusCode, QString("no_common_subnet"));
        QVERIFY(result.clientOnSelectedSubnet);
        QVERIFY(result.serverOnSelectedSubnet);
        QVERIFY(!result.sourceAddressSelected);
        QCOMPARE(probe.calls, QStringList{"interfaceFacts"});
    }

    void networkAndBroadcastAddressesAreRejectedAsPeers() {
        const QList<SessionConfig> configs = {
            {"synthetic0", "192.0.2.0", "192.0.2.30", 18081, {"/api/generate"}, false},
            {"synthetic0", "192.0.2.10", "192.0.2.255", 18081, {"/api/generate"}, false},
        };
        for (const auto &config : configs) {
            FakeLabProbe probe;
            const auto result = LabPreflight::run(config, probe);
            QVERIFY(!result.complete);
            QCOMPARE(result.statusCode, QString("no_common_subnet"));
            QVERIFY(!result.sourceAddressSelected);
            QVERIFY(!probe.calls.contains("connectTcp"));
        }
    }

    void extraLoopbackAndLinkLocalInterfaceAddressesAreIgnored() {
        FakeLabProbe probe;
        probe.facts.ipv4Addresses = {{"127.0.0.1", 8}, {"169.254.1.20", 16}, {"192.0.2.20", 24}};
        const auto result = LabPreflight::run(validConfig(), probe);
        QVERIFY(result.complete);
        QCOMPARE(probe.connectedSource, QString("192.0.2.20"));
        QCOMPARE(probe.calls, (QStringList{"interfaceFacts", "connectTcp"}));
    }

    void commonSubnetSelectsTheMatchingSourceWhenSeveralInterfaceAddressesExist() {
        FakeLabProbe probe;
        probe.facts.ipv4Addresses = {{"203.0.113.20", 24}, {"192.0.2.20", 24}};
        const auto result = LabPreflight::run(validConfig(), probe);
        QVERIFY(result.complete);
        QVERIFY(result.clientOnSelectedSubnet);
        QVERIFY(result.serverOnSelectedSubnet);
        QVERIFY(result.sourceAddressSelected);
        QCOMPARE(probe.connectedSource, QString("192.0.2.20"));
        QCOMPARE(probe.calls, (QStringList{"interfaceFacts", "connectTcp"}));
    }

    void malformedInterfaceFactsFailClosedBeforeTcpProbe() {
        const QList<InterfaceFacts> malformed = {
            {true, true, "02:00:00:00:00:20", {{"192.0.2.20", 33}}},
            {true, true, "02:00:00:00:00:20", {{"not-an-ip", 24}}},
            {true, true, "02:00:00:00:00:20", {{"2001:db8::20", 64}}},
        };
        for (const auto &facts : malformed) {
            FakeLabProbe probe;
            probe.facts = facts;
            const auto result = LabPreflight::run(validConfig(), probe);
            QVERIFY(!result.complete);
            QCOMPARE(result.statusCode, QString("invalid_interface_facts"));
            QCOMPARE(probe.calls, QStringList{"interfaceFacts"});
        }
    }

    void validMacIsRequiredBeforeTcpProbe() {
        FakeLabProbe probe;
        const QStringList invalidMacs{"", "00:00:00:00:00:00", "01:00:00:00:00:20", "not-a-mac"};
        for (const auto &mac : invalidMacs) {
            probe.facts.macAddress = mac;
            probe.calls.clear();
            const auto result = LabPreflight::run(validConfig(), probe);
            QVERIFY(!result.complete);
            QCOMPARE(result.statusCode, QString("interface_no_mac"));
            QVERIFY(!result.interfaceHasValidMac);
            QCOMPARE(probe.calls, QStringList{"interfaceFacts"});
        }
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
            QCOMPARE(probe.calls.size(), 2);
            QCOMPARE(probe.calls.last(), QString("connectTcp"));
        }
    }

    void sanitizedEvidenceOmitsLocalInterfaceAddressAndContainsNoMutationResult() {
        FakeLabProbe probe;
        probe.facts.ipv4Addresses = {{"198.51.100.20", 24}};
        const auto config = validConfig();
        const auto document = QJsonDocument(LabPreflight::run(config, probe).toSanitizedJson());
        const auto json = document.toJson(QJsonDocument::Compact);
        QVERIFY(!json.contains("198.51.100.20"));
        QVERIFY(!json.contains(config.clientIp.toUtf8()));
        QVERIFY(!json.contains(config.serverIp.toUtf8()));
        QVERIFY(json.contains("\"sanitized\":true"));
        QVERIFY(json.contains("\"layer2_arp_compatibility_proven\":false"));
        QVERIFY(json.contains("\"proxy_readiness_proven\":false"));
        QVERIFY(!json.contains("\"arp_modified\""));
        QVERIFY(!json.contains("\"pf_rules_changed\""));
        QVERIFY(!json.contains("\"forwarding_enabled\""));
        QCOMPARE(probe.calls.size(), 1);
    }
};

QTEST_GUILESS_MAIN(M6LabPreflightTests)
#include "M6LabPreflightTests.moc"
