#include "LabPreflight.hpp"

#include <QDateTime>
#include <QHostAddress>
#include <QJsonArray>
#include <QNetworkInterface>
#include <QTcpSocket>

namespace interceptor {
namespace {
class SystemLabProbe final : public LabProbe {
  public:
    bool interfaceExists(const QString &name) override {
        return QNetworkInterface::interfaceFromName(name).isValid();
    }

    bool interfaceUp(const QString &name) override {
        const auto interface = QNetworkInterface::interfaceFromName(name);
        return interface.isValid() && interface.flags().testFlag(QNetworkInterface::IsUp) &&
               interface.flags().testFlag(QNetworkInterface::IsRunning);
    }

    QStringList interfaceIPv4Addresses(const QString &name) override {
        QStringList addresses;
        const auto interface = QNetworkInterface::interfaceFromName(name);
        if (!interface.isValid())
            return addresses;
        for (const auto &entry : interface.addressEntries()) {
            const auto address = entry.ip();
            if (address.protocol() == QAbstractSocket::IPv4Protocol && !address.isLoopback() &&
                !address.isLinkLocal())
                addresses << address.toString();
        }
        return addresses;
    }

    TcpProbeResult connectTcp(const QString &interfaceName, const QString &serverIp, int serverPort,
                              int timeoutMs) override {
        QHostAddress destination;
        if (!destination.setAddress(serverIp))
            return TcpProbeResult::Error;

        const auto addresses = interfaceIPv4Addresses(interfaceName);
        if (addresses.isEmpty())
            return TcpProbeResult::Error;

        QHostAddress localAddress;
        if (!localAddress.setAddress(addresses.front()))
            return TcpProbeResult::Error;

        QTcpSocket socket;
        if (!socket.bind(localAddress, 0, QAbstractSocket::DefaultForPlatform))
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
    checks.insert("server_tcp", tcpStatus);
    return {{"schema", "llm-interceptor.lab-preflight.v1"},
            {"recorded_utc", QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)},
            {"sanitized", true},
            {"configured", configured},
            {"tcp_probe_scope", "source_address_bound_tcp_reachability"},
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
    result.interfaceFound = probe.interfaceExists(config.interfaceName);
    if (!result.interfaceFound) {
        result.statusCode = "interface_missing";
        return result;
    }
    result.interfaceUp = probe.interfaceUp(config.interfaceName);
    if (!result.interfaceUp) {
        result.statusCode = "interface_down";
        return result;
    }
    result.interfaceHasUsableIPv4 = !probe.interfaceIPv4Addresses(config.interfaceName).isEmpty();
    if (!result.interfaceHasUsableIPv4) {
        result.statusCode = "interface_no_ipv4";
        return result;
    }
    const auto tcp =
        probe.connectTcp(config.interfaceName, config.serverIp, config.serverPort, timeoutMs);
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
