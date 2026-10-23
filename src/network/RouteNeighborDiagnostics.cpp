#include "RouteNeighborDiagnostics.hpp"

#include <QDateTime>
#include <QElapsedTimer>
#include <QHostAddress>
#include <QJsonArray>
#include <QProcess>
#include <QRegularExpression>

namespace interceptor {
namespace {
const QString routePath = "/sbin/route";
const QString arpPath = "/usr/sbin/arp";

QString queryName(NetworkQuery query) {
    switch (query) {
    case NetworkQuery::ClientRoute:
        return "client_route";
    case NetworkQuery::ServerRoute:
        return "server_route";
    case NetworkQuery::ClientNeighbor:
        return "client_neighbor";
    case NetworkQuery::ServerNeighbor:
        return "server_neighbor";
    }
    return "unknown";
}

QString commandStatusName(NetworkCommandStatus status) {
    switch (status) {
    case NetworkCommandStatus::Completed:
        return "completed";
    case NetworkCommandStatus::NoEntry:
        return "no_entry";
    case NetworkCommandStatus::PermissionDenied:
        return "permission_denied";
    case NetworkCommandStatus::TimedOut:
        return "timed_out";
    case NetworkCommandStatus::OutputLimitExceeded:
        return "output_limit_exceeded";
    case NetworkCommandStatus::Failed:
        return "failed";
    }
    return "failed";
}

QString executableFor(NetworkQuery query) {
    switch (query) {
    case NetworkQuery::ClientRoute:
    case NetworkQuery::ServerRoute:
        return routePath;
    case NetworkQuery::ClientNeighbor:
    case NetworkQuery::ServerNeighbor:
        return arpPath;
    }
    return {};
}

QStringList argumentsFor(NetworkQuery query, const QString &interfaceName, const QString &ipv4) {
    switch (query) {
    case NetworkQuery::ClientRoute:
    case NetworkQuery::ServerRoute:
        return {"-n", "get", ipv4};
    case NetworkQuery::ClientNeighbor:
    case NetworkQuery::ServerNeighbor:
        return {"-i", interfaceName, "-n", ipv4};
    }
    return {};
}

bool permissionDeniedText(const QByteArray &text) {
    const auto lower = text.toLower();
    return lower.contains("operation not permitted") || lower.contains("permission denied") ||
           lower.contains("must be root") || lower.contains("requires root");
}

bool noEntryText(const QByteArray &text, const QString &ipv4) {
    const QRegularExpression expression(
        "^.*\\(" + QRegularExpression::escape(ipv4) +
            "\\)\\s+--\\s+no entry(?:\\s+on\\s+[A-Za-z][A-Za-z0-9_.:-]*)?\\s*$",
        QRegularExpression::MultilineOption | QRegularExpression::CaseInsensitiveOption);
    return expression.match(QString::fromUtf8(text)).hasMatch();
}

class SystemNetworkCommandRunner final : public NetworkCommandRunner {
  public:
    NetworkQueryOutput query(NetworkQuery query, const QString &interfaceName, const QString &ipv4,
                             int timeoutMs, qsizetype outputLimitBytes) override {
        QHostAddress address;
        const bool isNeighbor =
            query == NetworkQuery::ClientNeighbor || query == NetworkQuery::ServerNeighbor;
        static const QRegularExpression interfacePattern("^[A-Za-z][A-Za-z0-9_.:-]{0,63}$");
        if (timeoutMs < 1 || timeoutMs > RouteNeighborDiagnostics::maximumTimeoutMs ||
            outputLimitBytes < 1 ||
            outputLimitBytes > RouteNeighborDiagnostics::maximumOutputBytes ||
            !address.setAddress(ipv4) || address.protocol() != QAbstractSocket::IPv4Protocol ||
            address.toString() != ipv4 || !interfacePattern.match(interfaceName).hasMatch() ||
            executableFor(query).isEmpty())
            return {};

        QElapsedTimer timer;
        timer.start();
        QProcess process;
        process.setProgram(executableFor(query));
        process.setArguments(argumentsFor(query, interfaceName, ipv4));
        process.setProcessChannelMode(QProcess::SeparateChannels);
        process.start();

        NetworkQueryOutput result;
        if (!process.waitForStarted(timeoutMs)) {
            if (process.error() == QProcess::Timedout)
                result.status = NetworkCommandStatus::TimedOut;
            return result;
        }

        QByteArray permissionText;
        qsizetype observedBytes = 0;
        bool overflow = false;
        bool timedOut = false;
        auto drain = [&]() {
            const auto stdoutChunk = process.readAllStandardOutput();
            const auto stderrChunk = process.readAllStandardError();
            observedBytes += stdoutChunk.size() + stderrChunk.size();
            if (permissionText.size() < 4096)
                permissionText += stderrChunk.left(4096 - permissionText.size());
            if (observedBytes > outputLimitBytes) {
                overflow = true;
                process.kill();
            } else {
                result.standardOutput += stdoutChunk;
                result.standardError += stderrChunk;
            }
        };

        while (process.state() != QProcess::NotRunning) {
            drain();
            if (overflow)
                break;
            const int remaining = timeoutMs - static_cast<int>(timer.elapsed());
            if (remaining <= 0) {
                timedOut = true;
                process.kill();
                break;
            }
            process.waitForReadyRead(qMin(remaining, 100));
        }
        if (process.state() != QProcess::NotRunning)
            process.waitForFinished(100);
        drain();

        if (overflow) {
            result.status = NetworkCommandStatus::OutputLimitExceeded;
            result.standardOutput.clear();
            return result;
        }
        if (timedOut) {
            result.status = NetworkCommandStatus::TimedOut;
            result.standardOutput.clear();
            return result;
        }
        result.exitCode = process.exitCode();
        if (result.exitCode == 0) {
            result.status = NetworkCommandStatus::Completed;
            if (isNeighbor && noEntryText(result.standardOutput + result.standardError, ipv4))
                result.status = NetworkCommandStatus::NoEntry;
            return result;
        }
        result.status = permissionDeniedText(permissionText)
                            ? NetworkCommandStatus::PermissionDenied
                            : NetworkCommandStatus::Failed;
        if (isNeighbor && result.status == NetworkCommandStatus::Failed &&
            noEntryText(result.standardOutput + result.standardError, ipv4))
            result.status = NetworkCommandStatus::NoEntry;
        if (result.status != NetworkCommandStatus::NoEntry) {
            result.standardOutput.clear();
            result.standardError.clear();
        }
        return result;
    }
};

bool parseRoute(const QByteArray &output, const QString &expectedInterface,
                RouteNeighborTargetResult *result) {
    static const QRegularExpression interfacePattern(
        "^\\s*interface:\\s*([A-Za-z][A-Za-z0-9_.:-]*)\\s*$", QRegularExpression::MultilineOption);
    static const QRegularExpression gatewayPattern("^\\s*gateway:\\s*(\\S+)\\s*$",
                                                   QRegularExpression::MultilineOption);
    static const QRegularExpression flagsPattern("^\\s*flags:\\s*(.+?)\\s*$",
                                                 QRegularExpression::MultilineOption);
    const auto text = QString::fromUtf8(output);
    const auto interfaceMatch = interfacePattern.match(text);
    const auto gatewayMatch = gatewayPattern.match(text);
    const auto flagsMatch = flagsPattern.match(text);
    if (!interfaceMatch.hasMatch() || !flagsMatch.hasMatch())
        return false;

    static const QRegularExpression interfaceName("^[A-Za-z][A-Za-z0-9_.:-]{0,63}$");
    const auto observedInterface = interfaceMatch.captured(1);
    if (!interfaceName.match(observedInterface).hasMatch())
        return false;

    auto flagsText = flagsMatch.captured(1).trimmed();
    if (flagsText.startsWith('<') && flagsText.endsWith('>'))
        flagsText = flagsText.mid(1, flagsText.size() - 2);
    static const QRegularExpression validFlags("^[A-Za-z0-9_, ]+$");
    const auto flags = flagsText.split(',', Qt::SkipEmptyParts);
    if (!validFlags.match(flagsText).hasMatch() || flags.isEmpty())
        return false;
    const auto gateway = gatewayMatch.hasMatch() ? gatewayMatch.captured(1) : QString{};
    if (!gateway.isEmpty()) {
        static const QRegularExpression linkGateway("^link#[0-9]+$");
        QHostAddress gatewayAddress;
        if (!linkGateway.match(gateway).hasMatch() &&
            (!gatewayAddress.setAddress(gateway) ||
             gatewayAddress.protocol() != QAbstractSocket::IPv4Protocol ||
             gatewayAddress.toString() != gateway))
            return false;
    }

    result->routeRecognized = true;
    result->routeInterfaceMatches = observedInterface == expectedInterface;
    if (!gateway.isEmpty()) {
        result->routeDirectKnown = true;
        result->routeDirect = gateway.startsWith("link#");
    }
    return true;
}

bool isUnicastMac(const QString &mac) {
    static const QRegularExpression pattern("^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$");
    if (!pattern.match(mac).hasMatch())
        return false;
    bool firstOctetOk = false;
    const auto firstOctet = mac.left(2).toUInt(&firstOctetOk, 16);
    QString normalized = mac;
    normalized.remove(QLatin1Char(':'));
    return firstOctetOk && (firstOctet & 1U) == 0U &&
           normalized.compare("000000000000", Qt::CaseInsensitive) != 0;
}

bool parseNeighbor(const QByteArray &output, const QString &ipv4, const QString &expectedInterface,
                   RouteNeighborTargetResult *result) {
    static const QRegularExpression noEntryPattern(
        "^.*\\(([^)]+)\\)\\s+--\\s+no entry(?:\\s+on\\s+([A-Za-z][A-Za-z0-9_.:-]*))?\\s*$",
        QRegularExpression::MultilineOption | QRegularExpression::CaseInsensitiveOption);
    const auto noEntryMatch = noEntryPattern.match(QString::fromUtf8(output));
    if (noEntryMatch.hasMatch() && noEntryMatch.captured(1) == ipv4) {
        result->neighborRecognized = true;
        result->neighborResolved = false;
        result->neighborInterfaceMatches =
            !noEntryMatch.captured(2).isEmpty() && noEntryMatch.captured(2) == expectedInterface;
        return true;
    }

    static const QRegularExpression linePattern(
        "^\\s*(?:\\S+\\s+)?\\(([^)]+)\\)\\s+at\\s+(\\S+)\\s+on\\s+([A-Za-z][A-Za-z0-9_.:-]*)\\b",
        QRegularExpression::MultilineOption);
    const auto match = linePattern.match(QString::fromUtf8(output));
    if (!match.hasMatch() || match.captured(1) != ipv4)
        return false;

    result->neighborRecognized = true;
    result->neighborInterfaceMatches = match.captured(3) == expectedInterface;
    result->neighborResolved = isUnicastMac(match.captured(2));
    return true;
}

QJsonObject targetJson(const RouteNeighborTargetResult &target) {
    return {{"route_recognized", target.routeRecognized},
            {"route_interface_matches", target.routeInterfaceMatches},
            {"route_direct_known", target.routeDirectKnown},
            {"route_direct", target.routeDirect},
            {"neighbor_recognized", target.neighborRecognized},
            {"neighbor_resolved", target.neighborResolved},
            {"neighbor_interface_matches", target.neighborInterfaceMatches}};
}

} // namespace

QJsonObject RouteNeighborDiagnosticsResult::toSanitizedJson() const {
    QJsonArray errors;
    for (const auto &error : validationErrors)
        errors.append(error);
    QJsonArray queryResults;
    for (const auto &query : queries)
        queryResults.append(
            QJsonObject{{"query", queryName(query.query)}, {"status", query.status}});
    const QJsonObject checks{{"client", targetJson(client)}, {"server", targetJson(server)}};
    return {{"schema", "llm-interceptor.route-neighbor-diagnostics.v1"},
            {"recorded_utc", QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)},
            {"sanitized", true},
            {"observation_scope", "read_only_route_and_neighbor_table_inspection"},
            {"packet_egress_proven", false},
            {"layer2_or_arp_acceptance_proven", false},
            {"redirection_proven", false},
            {"checks", checks},
            {"queries", queryResults},
            {"timeout_ms_per_query", timeoutMs},
            {"complete", complete},
            {"status", statusCode},
            {"validation_errors", errors}};
}

RouteNeighborDiagnosticsResult RouteNeighborDiagnostics::collect(const SessionConfig &config,
                                                                 NetworkCommandRunner &runner,
                                                                 int timeoutMs) {
    RouteNeighborDiagnosticsResult result;
    result.timeoutMs = timeoutMs;
    result.validationErrors = config.validate();
    if (config.explicitProxy || config.interfaceName.isEmpty())
        result.validationErrors << "Route/neighbor inspection requires a selected LAN interface.";
    if (timeoutMs < 1 || timeoutMs > maximumTimeoutMs) {
        result.validationErrors << "Query timeout must be between 1 and 5000 milliseconds.";
        result.statusCode = "invalid_timeout";
        return result;
    }
    if (!result.validationErrors.isEmpty()) {
        result.statusCode = "invalid_config";
        return result;
    }
    result.configValid = true;

    struct QueryTarget {
        NetworkQuery query;
        QString ip;
        RouteNeighborTargetResult *target;
        bool isRoute;
    };
    QVector<QueryTarget> targets{
        {NetworkQuery::ClientRoute, config.clientIp, &result.client, true},
        {NetworkQuery::ServerRoute, config.serverIp, &result.server, true},
        {NetworkQuery::ClientNeighbor, config.clientIp, &result.client, false},
        {NetworkQuery::ServerNeighbor, config.serverIp, &result.server, false}};

    bool allRecognized = true;
    for (const auto &target : targets) {
        auto output = runner.query(target.query, config.interfaceName, target.ip, timeoutMs,
                                   maximumOutputBytes);
        result.queries.append({target.query, commandStatusName(output.status)});
        bool recognized = false;
        if (output.status == NetworkCommandStatus::Completed ||
            (!target.isRoute && output.status == NetworkCommandStatus::NoEntry)) {
            recognized =
                target.isRoute
                    ? parseRoute(output.standardOutput, config.interfaceName, target.target)
                    : parseNeighbor(output.standardOutput + output.standardError, target.ip,
                                    config.interfaceName, target.target);
        }
        allRecognized = allRecognized && recognized;
    }
    result.complete = allRecognized;
    result.statusCode = result.complete ? "observations_complete" : "observations_incomplete";
    return result;
}

NetworkCommandRunner &systemNetworkCommandRunner() {
    static SystemNetworkCommandRunner runner;
    return runner;
}

} // namespace interceptor
