#include "core/SessionConfig.hpp"
#include "network/LabPreflight.hpp"
#include "network/PfDiagnostics.hpp"
#include "network/RouteNeighborDiagnostics.hpp"

#include <QCommandLineParser>
#include <QCoreApplication>
#include <QFile>
#include <QJsonDocument>
#include <QSaveFile>
#include <QTextStream>

using namespace interceptor;

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName("lab_preflight");
    QCoreApplication::setApplicationVersion("0.1.0");

    QCommandLineParser parser;
    parser.setApplicationDescription(
        "Opt-in M6 diagnostics. Endpoint mode initiates one TCP handshake. Route/neighbor and "
        "PF modes perform read-only inspection. No mode changes local network configuration.");
    parser.addHelpOption();
    parser.addVersionOption();
    const auto interfaceOption =
        QCommandLineOption("interface", "Selected research interface.", "name");
    const auto clientOption =
        QCommandLineOption("client-ip", "Configured client IPv4 address.", "ipv4");
    const auto serverOption =
        QCommandLineOption("server-ip", "Configured server IPv4 address.", "ipv4");
    const auto portOption =
        QCommandLineOption("server-port", "Configured server TCP port.", "port");
    const auto timeoutOption = QCommandLineOption(
        "timeout-ms", "TCP connect timeout in milliseconds (1–5000; default 1500).", "ms",
        QString::number(LabPreflight::defaultTimeoutMs));
    const auto evidenceOption =
        QCommandLineOption("evidence", "Write the sanitized JSON result to this file.", "path");
    const auto pfDiagnosticsOption = QCommandLineOption(
        "pf-diagnostics",
        "Explicitly inspect read-only PF status, anchors, rules, and state candidates.");
    const auto routeNeighborOption = QCommandLineOption(
        "route-neighbor-diagnostics",
        "Explicitly inspect read-only routes and neighbor-table entries for client/server.");
    const auto sessionIdOption =
        QCommandLineOption("session-id", "M4 session identifier for the scoped PF anchor.", "id");
    const auto pfTimeoutOption = QCommandLineOption(
        "pf-timeout-ms", "Timeout per PF query in milliseconds (1–5000; default 3000).", "ms",
        QString::number(PfDiagnostics::defaultTimeoutMs));
    const auto networkTimeoutOption = QCommandLineOption(
        "network-timeout-ms", "Timeout per route/neighbor query (1–5000; default 1500).", "ms",
        QString::number(RouteNeighborDiagnostics::defaultTimeoutMs));
    parser.addOptions({interfaceOption, clientOption, serverOption, portOption, timeoutOption,
                       evidenceOption, pfDiagnosticsOption, routeNeighborOption, sessionIdOption,
                       pfTimeoutOption, networkTimeoutOption});
    parser.process(app);

    for (const auto &option : {interfaceOption, clientOption, serverOption}) {
        if (!parser.isSet(option)) {
            QTextStream(stderr) << "Missing required option: --" << option.names().front() << '\n';
            return 2;
        }
    }
    if (!parser.isSet(portOption) && !parser.isSet(routeNeighborOption)) {
        QTextStream(stderr) << "Missing required option: --" << portOption.names().front() << '\n';
        return 2;
    }

    bool portOk = true;
    bool timeoutOk = false;
    const int port = parser.isSet(portOption) ? parser.value(portOption).toInt(&portOk)
                                              : SessionConfig{}.serverPort;
    const int timeoutMs = parser.value(timeoutOption).toInt(&timeoutOk);
    SessionConfig config;
    config.interfaceName = parser.value(interfaceOption);
    config.clientIp = parser.value(clientOption);
    config.serverIp = parser.value(serverOption);
    config.serverPort = portOk ? port : 0;
    if (!portOk || !timeoutOk) {
        QTextStream(stderr) << "Port and timeout must be decimal integers.\n";
        return 2;
    }

    if (parser.isSet(pfDiagnosticsOption) && parser.isSet(routeNeighborOption)) {
        QTextStream(stderr) << "Select either PF or route/neighbor diagnostics.\n";
        return 2;
    }

    if (parser.isSet(routeNeighborOption)) {
        bool networkTimeoutOk = false;
        const int networkTimeoutMs = parser.value(networkTimeoutOption).toInt(&networkTimeoutOk);
        if (!networkTimeoutOk) {
            QTextStream(stderr) << "Network timeout must be a decimal integer.\n";
            return 2;
        }
        const auto result = RouteNeighborDiagnostics::collect(config, systemNetworkCommandRunner(),
                                                              networkTimeoutMs);
        const auto json = QJsonDocument(result.toSanitizedJson()).toJson(QJsonDocument::Indented);
        if (parser.isSet(evidenceOption)) {
            QSaveFile file(parser.value(evidenceOption));
            if (!file.open(QIODevice::WriteOnly) || file.write(json) != json.size() ||
                !file.commit()) {
                QTextStream(stderr) << "Could not write the evidence file.\n";
                return 2;
            }
        }
        QTextStream(stdout) << json;
        return result.complete ? 0 : 1;
    }

    if (parser.isSet(pfDiagnosticsOption)) {
        bool pfTimeoutOk = false;
        const int pfTimeoutMs = parser.value(pfTimeoutOption).toInt(&pfTimeoutOk);
        if (!parser.isSet(sessionIdOption) || !pfTimeoutOk) {
            QTextStream(stderr)
                << "PF diagnostics require --session-id and a decimal --pf-timeout-ms.\n";
            return 2;
        }
        const auto result = PfDiagnostics::collect(config, parser.value(sessionIdOption),
                                                   systemPfCommandRunner(), pfTimeoutMs);
        const auto json = QJsonDocument(result.toSanitizedJson()).toJson(QJsonDocument::Indented);
        if (parser.isSet(evidenceOption)) {
            QSaveFile file(parser.value(evidenceOption));
            if (!file.open(QIODevice::WriteOnly) || file.write(json) != json.size() ||
                !file.commit()) {
                QTextStream(stderr) << "Could not write the evidence file.\n";
                return 2;
            }
        }
        QTextStream(stdout) << json;
        return result.complete ? 0 : 1;
    }

    const auto result = LabPreflight::run(config, systemLabProbe(), timeoutMs);
    const auto json = QJsonDocument(result.toSanitizedJson()).toJson(QJsonDocument::Indented);
    if (parser.isSet(evidenceOption)) {
        QSaveFile file(parser.value(evidenceOption));
        if (!file.open(QIODevice::WriteOnly) || file.write(json) != json.size() || !file.commit()) {
            QTextStream(stderr) << "Could not write the evidence file.\n";
            return 2;
        }
    }
    QTextStream(stdout) << json;
    return result.complete ? 0 : 1;
}
