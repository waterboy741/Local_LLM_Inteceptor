#pragma once

#include "NetworkSession.hpp"

#include <QByteArray>
#include <QStringList>

#include <utility>

namespace interceptor {

enum class PfAnchorOperation { Install, RemoveRules };
enum class PfAnchorCommandStatus {
    Completed,
    PermissionDenied,
    TimedOut,
    OutputLimitExceeded,
    Failed
};

class PfAnchorCommand {
  public:
    PfAnchorOperation operation() const { return operation_; }
    const QString &anchor() const { return anchor_; }
    const QByteArray &standardInput() const { return standardInput_; }
    QString program() const;
    QStringList arguments() const;

  private:
    PfAnchorCommand(PfAnchorOperation operation, QString anchor, QByteArray standardInput)
        : operation_(operation), anchor_(std::move(anchor)),
          standardInput_(std::move(standardInput)) {}
    PfAnchorOperation operation_;
    QString anchor_;
    QByteArray standardInput_;
    friend class PfAnchorOperations;
};

struct PfAnchorCommandResult {
    PfAnchorCommandStatus status = PfAnchorCommandStatus::Failed;
    int exitCode = -1;
    bool started = false;
};

class PfAnchorAuthorization {
  public:
    virtual ~PfAnchorAuthorization() = default;
    // Query the effective process identity; callers cannot supply a root flag.
    virtual bool effectiveUserIsRoot() = 0;
    virtual bool pfEnabled() = 0;
    virtual bool verifySessionLease(const SessionSnapshot &snapshot, const QString &leaseToken) = 0;
    // Verify both main-ruleset filter and translation references are currently attached.
    virtual bool verifyActiveAttachment(const SessionSnapshot &snapshot) = 0;
    // Reject foreign/stale anchors and bind ownership to this exact session lease.
    virtual bool verifyAnchorOwnership(const SessionSnapshot &snapshot, const QString &leaseToken,
                                       PfAnchorOperation operation) = 0;
};

class PfAnchorCommandRunner {
  public:
    virtual ~PfAnchorCommandRunner() = default;
    virtual PfAnchorCommandResult execute(const PfAnchorCommand &command, int timeoutMs,
                                          qsizetype outputLimitBytes) = 0;
};

struct PfAnchorOperationResult {
    bool success = false;
    bool mayHaveApplied = false;
    QString statusCode;
};

class PfAnchorOperations {
  public:
    static constexpr int commandTimeoutMs = 3000;
    static constexpr qsizetype maximumOutputBytes = 64 * 1024;
    static constexpr qsizetype maximumRulesBytes = 32 * 1024;

    PfAnchorOperations(PfAnchorAuthorization &authorization, PfAnchorCommandRunner &runner)
        : authorization_(authorization), runner_(runner) {}

    PfAnchorOperationResult install(const SessionSnapshot &snapshot, const QString &leaseToken);
    PfAnchorOperationResult remove(const SessionSnapshot &snapshot, const QString &leaseToken);

  private:
    PfAnchorOperationResult apply(const SessionSnapshot &snapshot, const QString &leaseToken,
                                  bool install);
    PfAnchorAuthorization &authorization_;
    PfAnchorCommandRunner &runner_;
};

} // namespace interceptor
