#include "PfAnchorOperations.hpp"

#include <QRegularExpression>

namespace interceptor {
namespace {
const QString pfctlPath = "/sbin/pfctl";

QString commandStatusCode(PfAnchorCommandStatus status) {
    switch (status) {
    case PfAnchorCommandStatus::Completed:
        return "command_completed";
    case PfAnchorCommandStatus::PermissionDenied:
        return "permission_denied";
    case PfAnchorCommandStatus::TimedOut:
        return "timed_out";
    case PfAnchorCommandStatus::OutputLimitExceeded:
        return "output_limit_exceeded";
    case PfAnchorCommandStatus::Failed:
        return "command_failed";
    }
    return "command_failed";
}

bool validOwnedAnchor(const QString &anchor) {
    static const QRegularExpression pattern("^llm_interceptor/[A-Za-z0-9_-]{1,48}$");
    return pattern.match(anchor).hasMatch();
}

bool validLeaseToken(const QString &token) {
    if (token.isEmpty() || token.size() > 256)
        return false;
    for (const auto character : token)
        if (character.isNull() || character.isSpace() ||
            character.category() == QChar::Other_Control)
            return false;
    return true;
}
} // namespace

QString PfAnchorCommand::program() const { return pfctlPath; }

QStringList PfAnchorCommand::arguments() const {
    switch (operation_) {
    case PfAnchorOperation::Install:
        return {"-a", anchor_, "-f", "-"};
    case PfAnchorOperation::RemoveRules:
        return {"-a", anchor_, "-F", "rules"};
    }
    return {};
}

PfAnchorOperationResult PfAnchorOperations::install(const SessionSnapshot &snapshot,
                                                    const QString &leaseToken) {
    return apply(snapshot, leaseToken, true);
}

PfAnchorOperationResult PfAnchorOperations::remove(const SessionSnapshot &snapshot,
                                                   const QString &leaseToken) {
    return apply(snapshot, leaseToken, false);
}

PfAnchorOperationResult PfAnchorOperations::apply(const SessionSnapshot &snapshot,
                                                  const QString &leaseToken, bool installRules) {
    PfAnchorOperationResult result;
    const auto anchor = snapshot.anchor();
    if (!validOwnedAnchor(anchor) || (installRules && !snapshot.facts().anchorAttached)) {
        result.statusCode = "snapshot_preflight_unavailable";
        return result;
    }
    if (installRules) {
        const auto rules = snapshot.pfRules().toUtf8();
        if (rules.isEmpty() || rules.size() > maximumRulesBytes || rules.contains('\0')) {
            result.statusCode = "invalid_session_rules";
            return result;
        }
    }
    if (!authorization_.effectiveUserIsRoot()) {
        result.statusCode = "root_required";
        return result;
    }
    if (!validLeaseToken(leaseToken) || !authorization_.verifySessionLease(snapshot, leaseToken)) {
        result.statusCode = "session_lease_unverified";
        return result;
    }
    if (installRules) {
        if (!authorization_.pfEnabled()) {
            result.statusCode = "pf_disabled_or_unknown";
            return result;
        }
        if (!authorization_.verifyActiveAttachment(snapshot)) {
            result.statusCode = "active_attachment_unverified";
            return result;
        }
    }
    const auto operation =
        installRules ? PfAnchorOperation::Install : PfAnchorOperation::RemoveRules;
    if (!authorization_.verifyAnchorOwnership(snapshot, leaseToken, operation)) {
        result.statusCode = "anchor_ownership_unverified";
        return result;
    }

    const auto rules = installRules ? snapshot.pfRules().toUtf8() : QByteArray{};
    const PfAnchorCommand command(operation, anchor, rules);
    const auto commandResult = runner_.execute(command, commandTimeoutMs, maximumOutputBytes);
    result.mayHaveApplied = commandResult.started;
    if (commandResult.started && commandResult.processReaped &&
        commandResult.status == PfAnchorCommandStatus::Completed && commandResult.exitCode == 0) {
        result.success = true;
        result.statusCode = "completed";
        return result;
    }
    if (commandResult.started && !commandResult.processReaped)
        result.statusCode = "process_unreaped";
    else if (!commandResult.started && commandResult.status == PfAnchorCommandStatus::Completed)
        result.statusCode = "command_not_started";
    else if (commandResult.started && commandResult.status == PfAnchorCommandStatus::Completed &&
             commandResult.exitCode != 0)
        result.statusCode = "nonzero_exit";
    else
        result.statusCode = commandStatusCode(commandResult.status);
    return result;
}

} // namespace interceptor
