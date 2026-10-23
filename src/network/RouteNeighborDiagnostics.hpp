#pragma once

#include "core/SessionConfig.hpp"

#include <QByteArray>
#include <QJsonObject>
#include <QStringList>
#include <QVector>

namespace interceptor {

enum class NetworkQuery { ClientRoute, ServerRoute, ClientNeighbor, ServerNeighbor };
enum class NetworkCommandStatus {
    Completed,
    NoEntry,
    PermissionDenied,
    TimedOut,
    OutputLimitExceeded,
    Failed
};

struct NetworkQueryOutput {
    NetworkCommandStatus status = NetworkCommandStatus::Failed;
    int exitCode = -1;
    QByteArray standardOutput;
    QByteArray standardError;
};

class NetworkCommandRunner {
  public:
    virtual ~NetworkCommandRunner() = default;
    virtual NetworkQueryOutput query(NetworkQuery query, const QString &interfaceName,
                                     const QString &ipv4, int timeoutMs,
                                     qsizetype outputLimitBytes) = 0;
};

struct NetworkQueryDiagnostic {
    NetworkQuery query;
    QString status;
};

struct RouteNeighborTargetResult {
    bool routeRecognized = false;
    bool routeInterfaceMatches = false;
    bool routeDirectKnown = false;
    bool routeDirect = false;
    bool neighborRecognized = false;
    bool neighborResolved = false;
    bool neighborInterfaceMatches = false;
};

struct RouteNeighborDiagnosticsResult {
    bool configValid = false;
    bool complete = false;
    int timeoutMs = 0;
    QString statusCode;
    QStringList validationErrors;
    RouteNeighborTargetResult client;
    RouteNeighborTargetResult server;
    QVector<NetworkQueryDiagnostic> queries;

    QJsonObject toSanitizedJson() const;
};

class RouteNeighborDiagnostics {
  public:
    static constexpr int defaultTimeoutMs = 1500;
    static constexpr int maximumTimeoutMs = 5000;
    static constexpr qsizetype maximumOutputBytes = 32 * 1024;

    static RouteNeighborDiagnosticsResult collect(const SessionConfig &config,
                                                  NetworkCommandRunner &runner,
                                                  int timeoutMs = defaultTimeoutMs);
};

NetworkCommandRunner &systemNetworkCommandRunner();

} // namespace interceptor
