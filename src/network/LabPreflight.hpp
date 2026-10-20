#pragma once

#include "core/SessionConfig.hpp"

#include <QJsonObject>
#include <QStringList>

namespace interceptor {

enum class TcpProbeResult { Reachable, Refused, TimedOut, Error };

class LabProbe {
  public:
    virtual ~LabProbe() = default;
    virtual bool interfaceExists(const QString &name) = 0;
    virtual bool interfaceUp(const QString &name) = 0;
    virtual QStringList interfaceIPv4Addresses(const QString &name) = 0;
    virtual TcpProbeResult connectTcp(const QString &interfaceName, const QString &serverIp,
                                      int serverPort, int timeoutMs) = 0;
};

struct LabPreflightResult {
    bool configValid = false;
    bool interfaceFound = false;
    bool interfaceUp = false;
    bool interfaceHasUsableIPv4 = false;
    bool serverTcpReachable = false;
    bool complete = false;
    int timeoutMs = 0;
    QString statusCode;
    QString tcpStatus = "not_checked";
    QStringList validationErrors;
    SessionConfig config;

    QJsonObject toSanitizedJson() const;
};

class LabPreflight {
  public:
    static constexpr int defaultTimeoutMs = 1500;
    static constexpr int maximumTimeoutMs = 5000;

    static LabPreflightResult run(const SessionConfig &config, LabProbe &probe,
                                  int timeoutMs = defaultTimeoutMs);
};

// Production adapter is read-only with respect to local configuration. It does initiate one
// outbound TCP connection, which can create connection state or a log on the remote endpoint.
// It never changes interface, routing, PF, ARP, or sysctl state.
LabProbe &systemLabProbe();

} // namespace interceptor
