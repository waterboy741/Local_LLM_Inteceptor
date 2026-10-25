#pragma once

#include <QString>
#include <optional>

namespace interceptor {

enum class PfRecoveryJournalStatus {
    Ready,
    InvalidDirectory,
    LockFailed,
    JournalMissing,
    JournalPresent,
    UnsafeJournal,
    InvalidJournal,
    InvalidSessionId,
    SessionConflict,
    IoFailed,
    DurabilityUncertain,
    Persisted,
    Cleared
};

struct PfRecoveryRecord {
    QString sessionId;
    QString anchor;
    QString phase;
};

struct PfRecoveryJournalReadResult {
    PfRecoveryJournalStatus status = PfRecoveryJournalStatus::IoFailed;
    std::optional<PfRecoveryRecord> record;
};

class PfRecoveryJournal final {
  public:
    static PfRecoveryJournal open(int trustedDirectoryFd);

    PfRecoveryJournal(const PfRecoveryJournal &) = delete;
    PfRecoveryJournal &operator=(const PfRecoveryJournal &) = delete;
    PfRecoveryJournal(PfRecoveryJournal &&other) noexcept;
    PfRecoveryJournal &operator=(PfRecoveryJournal &&other) = delete;
    ~PfRecoveryJournal();

    bool valid() const noexcept;
    PfRecoveryJournalStatus status() const noexcept;
    PfRecoveryJournalReadResult read() const;
    PfRecoveryJournalStatus persistCleanupNeeded(const QString &sessionId) const;
    PfRecoveryJournalStatus clearAfterVerifiedCleanup(const QString &sessionId) const;

    static QString statusName(PfRecoveryJournalStatus status);

  private:
    explicit PfRecoveryJournal(PfRecoveryJournalStatus status, int directoryFd = -1) noexcept;

    PfRecoveryJournalStatus status_;
    int directoryFd_;
};

} // namespace interceptor
