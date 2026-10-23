#include "LabPreflight.hpp"

#include <QDateTime>
#include <QHostAddress>
#include <QJsonArray>
#include <QNetworkInterface>
#include <QRegularExpression>
#include <QTcpSocket>

#include <algorithm>

namespace interceptor {
namespace {
class SystemLabProbe final : public LabProbe {
  public:
    InterfaceFacts interfaceFacts(const QString &name) override {
        InterfaceFacts facts;
        const auto interface = QNetworkInterface::interfaceFromName(name);
        if (!interface.isValid())
            return facts;
        facts.found = true;
        facts.up = interface.flags().testFlag(QNetworkInterface::IsUp) &&
                   interface.flags().testFlag(QNetworkInterface::IsRunning);
        facts.macAddress = interface.hardwareAddress();
        for (const auto &entry : interface.addressEntries()) {
            const auto address = entry.ip();
            if (address.protocol() == QAbstractSocket::IPv4Protocol)
                facts.ipv4Addresses.append({address.toString(), entry.prefixLength()});
        }
        return facts;
    }

    TcpProbeResult connectTcp(const QString &interfaceName, const QString &sourceIpv4,
                              const QString &serverIp, int serverPort, int timeoutMs) override {
        QHostAddress destination;
        QHostAddress source;
        if (!destination.setAddress(serverIp) || !source.setAddress(sourceIpv4))
            return TcpProbeResult::Error;

        const auto currentFacts = interfaceFacts(interfaceName);
        if (!currentFacts.found || !currentFacts.up ||
            std::none_of(currentFacts.ipv4Addresses.cbegin(), currentFacts.ipv4Addresses.cend(),
                         [&sourceIpv4](const InterfaceAddressFact &fact) {
                             return fact.ipv4 == sourceIpv4;
                         }))
            return TcpProbeResult::Error;

        QTcpSocket socket;
        if (!socket.bind(source, 0, QAbstractSocket::DefaultForPlatform))
            return TcpProbeResult::Error;
        socket.connectToHost(destination, static_cast<quint16>(serverPort));
        if (socket.waitForConnected(timeoutMs)) {
            socket.abort();
            return TcpProbeResult::Reachable;
        }
        if (socket.error() == QAbstractSocket::SocketTimeoutError)
            return TcpProbeResult::TimedOut;
        if (socket.error() == QAbstractSocket::ConnectionRefusedError ||
            socket.error() == QAbstractSocket::HostNotFoundError)
            return TcpProbeResult::Refused;
        return TcpProbeResult::Error;
    }
};

bool isUsableMac(const QString &mac) {
    static const QRegularExpression pattern(QStringLiteral("^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$"));
    if (!pattern.match(mac).hasMatch())
        return false;
    const auto firstOctet = mac.left(2).toUInt(nullptr, 16);
    QString normalized = mac;
    normalized.remove(QLatin1Char(':'));
    normalized = normalized.toLower();
    return (firstOctet & 1U) == 0U && normalized != QStringLiteral("000000000000");
}

bool usableUnicastIpv4(const QHostAddress &address) {
    const auto value = address.toIPv4Address();
    const auto firstOctet = value >> 24;
    return address.protocol() == QAbstractSocket::IPv4Protocol && value != 0 &&
           value != 0xffffffffU && firstOctet > 0 && firstOctet < 224 && !address.isLoopback() &&
           !address.isLinkLocal();
}

bool sameSubnet(const QHostAddress &left, const QHostAddress &right, int prefixLength) {
    const quint32 mask = 0xffffffffU << (32 - prefixLength);
    return (left.toIPv4Address() & mask) == (right.toIPv4Address() & mask);
}

bool isSubnetHostAddress(const QHostAddress &address, int prefixLength) {
    const quint32 mask = 0xffffffffU << (32 - prefixLength);
    const auto value = address.toIPv4Address();
    const auto network = value & mask;
    return value != network && value != (network | ~mask);
}

bool peerIsHostOnSubnet(const QHostAddress &peer, const QHostAddress &local, int prefixLength) {
    if (!usableUnicastIpv4(peer) || !sameSubnet(peer, local, prefixLength))
        return false;
    const quint32 mask = 0xffffffffU << (32 - prefixLength);
    const auto peerValue = peer.toIPv4Address();
    const auto network = local.toIPv4Address() & mask;
    const auto broadcast = network | ~mask;
    return peerValue != network && peerValue != broadcast;
}

QString tcpCode(TcpProbeResult result) {
    switch (result) {
    case TcpProbeResult::Reachable:
        return "reachable";
    case TcpProbeResult::Refused:
        return "refused";
    case TcpProbeResult::TimedOut:
        return "timed_out";
    case TcpProbeResult::Error:
        return "error";
    }
    return "error";
}
} // namespace

QJsonObject LabPreflightResult::toSanitizedJson() const {
    QJsonArray errors;
    for (const auto &error : validationErrors)
        errors.append(error);
    QJsonObject configured;
    configured.insert("interface", !config.interfaceName.isEmpty());
    configured.insert("client_ipv4", !config.clientIp.isEmpty());
    configured.insert("server_ipv4", !config.serverIp.isEmpty());
    configured.insert("server_tcp_port", config.serverPort >= 1 && config.serverPort <= 65535);
    QJsonObject checks;
    checks.insert("configuration_valid", configValid);
    checks.insert("interface_found", interfaceFound);
    checks.insert("interface_up", interfaceUp);
    checks.insert("interface_has_usable_ipv4", interfaceHasUsableIPv4);
    checks.insert("interface_has_valid_mac", interfaceHasValidMac);
    checks.insert("client_on_selected_subnet", clientOnSelectedSubnet);
    checks.insert("server_on_selected_subnet", serverOnSelectedSubnet);
    checks.insert("source_address_selected", sourceAddressSelected);
    checks.insert("server_tcp", tcpStatus);
    return {{"schema", "llm-interceptor.lab-preflight.v2"},
            {"recorded_utc", QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)},
            {"sanitized", true},
            {"configured", configured},
            {"interface_fact_scope", "selected_interface_ip_prefix_mac_and_subnet_membership"},
            {"tcp_probe_scope", "source_address_bound_tcp_reachability_not_interface_egress_proof"},
            {"layer2_arp_compatibility_proven", false},
            {"proxy_readiness_proven", false},
            {"checks", checks},
            {"timeout_ms", timeoutMs},
            {"complete", complete},
            {"status", statusCode},
            {"validation_errors", errors}};
}

LabPreflightResult LabPreflight::run(const SessionConfig &config, LabProbe &probe, int timeoutMs) {
    LabPreflightResult result;
    result.config = config;
    result.timeoutMs = timeoutMs;
    result.validationErrors = config.validate();
    if (timeoutMs < 1 || timeoutMs > maximumTimeoutMs) {
        result.validationErrors << "Probe timeout must be between 1 and 5000 milliseconds.";
        result.statusCode = "invalid_timeout";
        return result;
    }
    if (!result.validationErrors.isEmpty()) {
        result.statusCode = "invalid_config";
        return result;
    }
    result.configValid = true;
    const auto facts = probe.interfaceFacts(config.interfaceName);
    result.interfaceFound = facts.found;
    if (!result.interfaceFound) {
        result.statusCode = "interface_missing";
        return result;
    }
    result.interfaceUp = facts.up;
    if (!result.interfaceUp) {
        result.statusCode = "interface_down";
        return result;
    }
    QHostAddress clientAddress;
    QHostAddress serverAddress;
    clientAddress.setAddress(config.clientIp);
    serverAddress.setAddress(config.serverIp);
    result.interfaceHasValidMac = isUsableMac(facts.macAddress);
    bool invalidAddressFact = false;
    QString selectedSourceAddress;
    for (const auto &addressFact : facts.ipv4Addresses) {
        QHostAddress localAddress;
        if (!localAddress.setAddress(addressFact.ipv4) || addressFact.prefixLength < 1 ||
            addressFact.prefixLength > 30) {
            invalidAddressFact = true;
            continue;
        }
        if (!usableUnicastIpv4(localAddress))
            continue;
        if (!isSubnetHostAddress(localAddress, addressFact.prefixLength)) {
            invalidAddressFact = true;
            continue;
        }
        result.interfaceHasUsableIPv4 = true;
        const bool clientMatches =
            peerIsHostOnSubnet(clientAddress, localAddress, addressFact.prefixLength);
        const bool serverMatches =
            peerIsHostOnSubnet(serverAddress, localAddress, addressFact.prefixLength);
        result.clientOnSelectedSubnet = result.clientOnSelectedSubnet || clientMatches;
        result.serverOnSelectedSubnet = result.serverOnSelectedSubnet || serverMatches;
        if (clientMatches && serverMatches && selectedSourceAddress.isEmpty()) {
            selectedSourceAddress = addressFact.ipv4;
        }
    }
    if (invalidAddressFact) {
        result.statusCode = "invalid_interface_facts";
        return result;
    }
    if (!result.interfaceHasUsableIPv4) {
        result.statusCode = "interface_no_ipv4";
        return result;
    }
    if (!result.interfaceHasValidMac) {
        result.statusCode = "interface_no_mac";
        return result;
    }
    if (selectedSourceAddress.isEmpty()) {
        result.statusCode = "no_common_subnet";
        return result;
    }
    result.sourceAddressSelected = true;
    const auto tcp = probe.connectTcp(config.interfaceName, selectedSourceAddress, config.serverIp,
                                      config.serverPort, timeoutMs);
    result.tcpStatus = tcpCode(tcp);
    result.serverTcpReachable = tcp == TcpProbeResult::Reachable;
    result.complete = result.serverTcpReachable;
    result.statusCode = "tcp_" + result.tcpStatus;
    return result;
}

LabProbe &systemLabProbe() {
    static SystemLabProbe probe;
    return probe;
}

} // namespace interceptor
