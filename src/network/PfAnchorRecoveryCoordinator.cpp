#include "PfAnchorRecoveryCoordinator.hpp"

namespace interceptor {

PfAnchorRecoveryCoordinatorResult
PfAnchorRecoveryCoordinator::install(const SessionSnapshot &snapshot, const QString &leaseToken) {
    PfAnchorRecoveryCoordinatorResult result;
    result.journalStatus = journal_.persistCleanupNeeded(snapshot.sessionId());
    if (result.journalStatus != PfRecoveryJournalStatus::Persisted) {
        result.statusCode = "journal_not_durable";
        result.cleanupPending = true;
        return result;
    }

    PfAnchorOperationResult operationResult;
    try {
        operationResult = operations_.install(snapshot, leaseToken);
    } catch (...) {
        result.operationStatus = "operation_exception";
        result.operationMayHaveApplied = true;
        result.statusCode = "install_failed_cleanup_pending";
        result.cleanupPending = true;
        return result;
    }
    result.operationStatus = operationResult.statusCode;
    result.operationMayHaveApplied = operationResult.mayHaveApplied;
    result.cleanupPending = true;
    if (!operationResult.success) {
        result.statusCode = "install_failed_cleanup_pending";
        return result;
    }
    result.success = true;
    result.statusCode = "installed_cleanup_pending";
    return result;
}

PfAnchorRecoveryCoordinatorResult
PfAnchorRecoveryCoordinator::cleanup(const SessionSnapshot &snapshot, const QString &leaseToken) {
    PfAnchorRecoveryCoordinatorResult result;
    const auto journalResult = journal_.read();
    result.journalStatus = journalResult.status;
    if (journalResult.status != PfRecoveryJournalStatus::JournalPresent || !journalResult.record) {
        result.statusCode = journalResult.status == PfRecoveryJournalStatus::JournalMissing
                                ? "cleanup_journal_missing"
                                : "cleanup_journal_unavailable";
        result.cleanupPending = true;
        return result;
    }
    if (journalResult.record->sessionId != snapshot.sessionId() ||
        journalResult.record->anchor != snapshot.anchor() ||
        journalResult.record->phase != "cleanup_needed") {
        result.statusCode = "cleanup_journal_mismatch";
        result.cleanupPending = true;
        return result;
    }

    PfAnchorOperationResult operationResult;
    try {
        operationResult = operations_.remove(snapshot, leaseToken);
    } catch (...) {
        result.operationStatus = "operation_exception";
        result.operationMayHaveApplied = true;
        result.statusCode = "cleanup_remove_failed_pending";
        result.cleanupPending = true;
        return result;
    }
    result.operationStatus = operationResult.statusCode;
    result.operationMayHaveApplied = operationResult.mayHaveApplied;
    if (!operationResult.success) {
        result.statusCode = "cleanup_remove_failed_pending";
        result.cleanupPending = true;
        return result;
    }

    try {
        result.verification = verifier_.verifyOwnedAnchorEmpty(snapshot);
    } catch (...) {
        result.verification = PfAnchorCleanupVerification::Unknown;
    }
    if (result.verification != PfAnchorCleanupVerification::Empty) {
        result.statusCode = result.verification == PfAnchorCleanupVerification::NotEmpty
                                ? "cleanup_anchor_not_empty"
                                : "cleanup_anchor_unverified";
        result.cleanupPending = true;
        return result;
    }

    result.journalStatus = journal_.clearAfterVerifiedCleanup(snapshot.sessionId());
    if (result.journalStatus != PfRecoveryJournalStatus::Cleared) {
        result.statusCode = "cleanup_journal_clear_uncertain";
        result.cleanupPending = true;
        return result;
    }
    result.success = true;
    result.statusCode = "cleanup_complete";
    result.cleanupPending = false;
    return result;
}

} // namespace interceptor
