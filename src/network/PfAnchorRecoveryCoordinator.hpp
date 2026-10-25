#pragma once

#include "PfAnchorOperations.hpp"
#include "PfRecoveryJournal.hpp"

namespace interceptor {

enum class PfAnchorCleanupVerification { NotRequested, Empty, NotEmpty, Unknown };

class PfAnchorCleanupVerifier {
  public:
    virtual ~PfAnchorCleanupVerifier() = default;
    // Empty means a fresh read-only check confirmed this exact snapshot anchor has no rules.
    virtual PfAnchorCleanupVerification verifyOwnedAnchorEmpty(const SessionSnapshot &snapshot) = 0;
};

struct PfAnchorRecoveryCoordinatorResult {
    bool success = false;
    bool cleanupPending = false;
    bool operationMayHaveApplied = false;
    QString statusCode;
    QString operationStatus;
    PfRecoveryJournalStatus journalStatus = PfRecoveryJournalStatus::Ready;
    PfAnchorCleanupVerification verification = PfAnchorCleanupVerification::NotRequested;
};

class PfAnchorRecoveryCoordinator final {
  public:
    PfAnchorRecoveryCoordinator(PfAnchorOperations &operations, PfRecoveryJournal &journal,
                                PfAnchorCleanupVerifier &verifier)
        : operations_(operations), journal_(journal), verifier_(verifier) {}

    PfAnchorRecoveryCoordinatorResult install(const SessionSnapshot &snapshot,
                                              const QString &leaseToken);
    PfAnchorRecoveryCoordinatorResult cleanup(const SessionSnapshot &snapshot,
                                              const QString &leaseToken);

  private:
    PfAnchorOperations &operations_;
    PfRecoveryJournal &journal_;
    PfAnchorCleanupVerifier &verifier_;
};

} // namespace interceptor
