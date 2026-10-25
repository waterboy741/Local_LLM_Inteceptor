#include "PfRecoveryJournal.hpp"

#include <QByteArray>
#include <QVector>

#include <atomic>
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace interceptor {
namespace {
constexpr char journalFileName[] = "llm_interceptor.recovery.journal";
constexpr char guardFileName[] = "llm_interceptor.recovery.lock";
constexpr char journalSchema[] = "llm-interceptor.pf-recovery.v1";
constexpr char journalPhase[] = "cleanup_needed";
constexpr qsizetype maximumJournalBytes = 512;
constexpr mode_t privateDirectoryMode = 0700;
constexpr mode_t privateFileMode = 0600;
std::atomic<unsigned long long> temporaryCounter{0};

bool privateDirectory(int directoryFd) {
    struct stat info{};
    return fstat(directoryFd, &info) == 0 && S_ISDIR(info.st_mode) && info.st_uid == geteuid() &&
           (info.st_mode & 07777) == privateDirectoryMode;
}

bool safeRegularFile(int fileFd) {
    struct stat info{};
    return fstat(fileFd, &info) == 0 && S_ISREG(info.st_mode) && info.st_uid == geteuid() &&
           (info.st_mode & 07777) == privateFileMode && info.st_nlink == 1;
}

bool validSessionId(const QString &sessionId, QByteArray *encoded) {
    *encoded = sessionId.toUtf8();
    if (QString::fromLatin1(*encoded) != sessionId || encoded->isEmpty() || encoded->size() > 48)
        return false;
    const auto isAllowed = [](char value) {
        return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
               (value >= '0' && value <= '9') || value == '_' || value == '-';
    };
    for (const char value : *encoded)
        if (!isAllowed(value))
            return false;
    return true;
}

QByteArray serializeRecord(const QByteArray &sessionId) {
    return QByteArray("schema=") + journalSchema + "\nsession_id=" + sessionId +
           "\nanchor=llm_interceptor/" + sessionId + "\nphase=" + journalPhase + "\n";
}

bool writeAll(int fd, const QByteArray &bytes) {
    qsizetype offset = 0;
    while (offset < bytes.size()) {
        const auto written =
            write(fd, bytes.constData() + offset, static_cast<size_t>(bytes.size() - offset));
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return false;
        offset += written;
    }
    return true;
}

struct GuardLock {
    GuardLock() = default;
    GuardLock(const GuardLock &) = delete;
    GuardLock &operator=(const GuardLock &) = delete;
    GuardLock(GuardLock &&other) noexcept : fd(other.fd), status(other.status) { other.fd = -1; }
    GuardLock &operator=(GuardLock &&other) noexcept {
        if (this == &other)
            return *this;
        if (fd >= 0) {
            flock(fd, LOCK_UN);
            close(fd);
        }
        fd = other.fd;
        status = other.status;
        other.fd = -1;
        return *this;
    }

    int fd = -1;
    PfRecoveryJournalStatus status = PfRecoveryJournalStatus::LockFailed;

    ~GuardLock() {
        if (fd >= 0) {
            flock(fd, LOCK_UN);
            close(fd);
        }
    }
};

GuardLock acquireGuard(int directoryFd) {
    GuardLock guard;
    guard.fd = openat(directoryFd, guardFileName,
                      O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, privateFileMode);
    if (guard.fd < 0) {
        if (errno == ELOOP || errno == EISDIR)
            guard.status = PfRecoveryJournalStatus::UnsafeJournal;
        else
            guard.status = PfRecoveryJournalStatus::LockFailed;
        return guard;
    }
    if (!safeRegularFile(guard.fd)) {
        close(guard.fd);
        guard.fd = -1;
        guard.status = PfRecoveryJournalStatus::UnsafeJournal;
        return guard;
    }
    int result;
    do {
        result = flock(guard.fd, LOCK_EX | LOCK_NB);
    } while (result < 0 && errno == EINTR);
    if (result < 0) {
        close(guard.fd);
        guard.fd = -1;
        guard.status = PfRecoveryJournalStatus::LockFailed;
        return guard;
    }
    if (!safeRegularFile(guard.fd)) {
        flock(guard.fd, LOCK_UN);
        close(guard.fd);
        guard.fd = -1;
        guard.status = PfRecoveryJournalStatus::UnsafeJournal;
        return guard;
    }
    guard.status = PfRecoveryJournalStatus::Ready;
    return guard;
}

PfRecoveryJournalReadResult readRecordUnlocked(int directoryFd) {
    PfRecoveryJournalReadResult result;
    const int file =
        openat(directoryFd, journalFileName, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (file < 0) {
        result.status = errno == ENOENT ? PfRecoveryJournalStatus::JournalMissing
                                        : (errno == ELOOP || errno == EISDIR
                                               ? PfRecoveryJournalStatus::UnsafeJournal
                                               : PfRecoveryJournalStatus::IoFailed);
        return result;
    }
    if (!safeRegularFile(file)) {
        close(file);
        result.status = PfRecoveryJournalStatus::UnsafeJournal;
        return result;
    }

    struct stat before{};
    if (fstat(file, &before) < 0 || before.st_size <= 0 || before.st_size > maximumJournalBytes) {
        close(file);
        result.status = PfRecoveryJournalStatus::InvalidJournal;
        return result;
    }
    QByteArray bytes;
    bytes.resize(static_cast<qsizetype>(before.st_size) + 1);
    ssize_t count;
    do {
        count = read(file, bytes.data(), static_cast<size_t>(bytes.size()));
    } while (count < 0 && errno == EINTR);
    struct stat after{};
    const bool statOk = fstat(file, &after) == 0;
    const int closeResult = close(file);
    if (count < 0 || !statOk || closeResult < 0 || count != before.st_size ||
        after.st_dev != before.st_dev || after.st_ino != before.st_ino ||
        after.st_size != before.st_size) {
        result.status = PfRecoveryJournalStatus::IoFailed;
        return result;
    }
    bytes.resize(static_cast<qsizetype>(count));

    if (bytes.size() > maximumJournalBytes || bytes.contains('\r') ||
        QString::fromUtf8(bytes).toUtf8() != bytes) {
        result.status = PfRecoveryJournalStatus::InvalidJournal;
        return result;
    }
    const auto lines = bytes.split('\n');
    if (lines.size() != 5 || !lines[4].isEmpty() ||
        lines[0] != QByteArray("schema=") + journalSchema || !lines[1].startsWith("session_id=") ||
        !lines[2].startsWith("anchor=") || lines[3] != QByteArray("phase=") + journalPhase) {
        result.status = PfRecoveryJournalStatus::InvalidJournal;
        return result;
    }
    const QByteArray sessionIdBytes = lines[1].mid(sizeof("session_id=") - 1);
    const QString sessionId = QString::fromLatin1(sessionIdBytes);
    QByteArray validatedId;
    if (!validSessionId(sessionId, &validatedId) || validatedId != sessionIdBytes ||
        lines[2] != QByteArray("anchor=llm_interceptor/") + sessionIdBytes) {
        result.status = PfRecoveryJournalStatus::InvalidJournal;
        return result;
    }

    result.status = PfRecoveryJournalStatus::JournalPresent;
    result.record = PfRecoveryRecord{sessionId, "llm_interceptor/" + sessionId,
                                     QString::fromLatin1(journalPhase)};
    return result;
}

PfRecoveryJournalStatus writeRecordUnlocked(int directoryFd, const QByteArray &record) {
    QByteArray temporaryName;
    int temporaryFd = -1;
    for (int attempt = 0; attempt < 64; ++attempt) {
        const auto sequence = temporaryCounter.fetch_add(1, std::memory_order_relaxed);
        temporaryName = QByteArray(".llm_interceptor.recovery.tmp.") +
                        QByteArray::number(static_cast<qlonglong>(getpid())) + "." +
                        QByteArray::number(static_cast<qulonglong>(sequence));
        temporaryFd = openat(directoryFd, temporaryName.constData(),
                             O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
                             privateFileMode);
        if (temporaryFd >= 0)
            break;
        if (errno != EEXIST)
            return PfRecoveryJournalStatus::IoFailed;
    }
    if (temporaryFd < 0)
        return PfRecoveryJournalStatus::IoFailed;

    if (!safeRegularFile(temporaryFd) || !writeAll(temporaryFd, record) || fsync(temporaryFd) < 0) {
        close(temporaryFd);
        unlinkat(directoryFd, temporaryName.constData(), 0);
        return PfRecoveryJournalStatus::IoFailed;
    }
    if (close(temporaryFd) < 0) {
        unlinkat(directoryFd, temporaryName.constData(), 0);
        return PfRecoveryJournalStatus::IoFailed;
    }
    if (renameat(directoryFd, temporaryName.constData(), directoryFd, journalFileName) < 0) {
        unlinkat(directoryFd, temporaryName.constData(), 0);
        return PfRecoveryJournalStatus::IoFailed;
    }
    if (fsync(directoryFd) < 0)
        return PfRecoveryJournalStatus::DurabilityUncertain;
    return PfRecoveryJournalStatus::Persisted;
}

} // namespace

PfRecoveryJournal::PfRecoveryJournal(PfRecoveryJournalStatus status, int directoryFd) noexcept
    : status_(status), directoryFd_(directoryFd) {}

PfRecoveryJournal PfRecoveryJournal::open(int trustedDirectoryFd) {
    if (!privateDirectory(trustedDirectoryFd))
        return PfRecoveryJournal(PfRecoveryJournalStatus::InvalidDirectory);
    const int directoryFd = fcntl(trustedDirectoryFd, F_DUPFD_CLOEXEC, 0);
    if (directoryFd < 0 || !privateDirectory(directoryFd)) {
        if (directoryFd >= 0)
            close(directoryFd);
        return PfRecoveryJournal(PfRecoveryJournalStatus::InvalidDirectory);
    }
    return PfRecoveryJournal(PfRecoveryJournalStatus::Ready, directoryFd);
}

PfRecoveryJournal::PfRecoveryJournal(PfRecoveryJournal &&other) noexcept
    : status_(other.status_), directoryFd_(other.directoryFd_) {
    other.status_ = PfRecoveryJournalStatus::InvalidDirectory;
    other.directoryFd_ = -1;
}

PfRecoveryJournal::~PfRecoveryJournal() {
    if (directoryFd_ >= 0)
        close(directoryFd_);
}

bool PfRecoveryJournal::valid() const noexcept {
    return directoryFd_ >= 0 && status_ == PfRecoveryJournalStatus::Ready &&
           privateDirectory(directoryFd_);
}

PfRecoveryJournalStatus PfRecoveryJournal::status() const noexcept { return status_; }

PfRecoveryJournalReadResult PfRecoveryJournal::read() const {
    if (directoryFd_ < 0 || status_ != PfRecoveryJournalStatus::Ready)
        return {status_, std::nullopt};
    if (!privateDirectory(directoryFd_))
        return {PfRecoveryJournalStatus::InvalidDirectory, std::nullopt};
    auto guard = acquireGuard(directoryFd_);
    if (guard.status != PfRecoveryJournalStatus::Ready)
        return {guard.status, std::nullopt};
    return readRecordUnlocked(directoryFd_);
}

PfRecoveryJournalStatus PfRecoveryJournal::persistCleanupNeeded(const QString &sessionId) const {
    if (directoryFd_ < 0 || status_ != PfRecoveryJournalStatus::Ready)
        return status_;
    if (!privateDirectory(directoryFd_))
        return PfRecoveryJournalStatus::InvalidDirectory;
    QByteArray sessionIdBytes;
    if (!validSessionId(sessionId, &sessionIdBytes))
        return PfRecoveryJournalStatus::InvalidSessionId;
    auto guard = acquireGuard(directoryFd_);
    if (guard.status != PfRecoveryJournalStatus::Ready)
        return guard.status;
    const auto existing = readRecordUnlocked(directoryFd_);
    if (existing.status == PfRecoveryJournalStatus::JournalPresent)
        return PfRecoveryJournalStatus::SessionConflict;
    if (existing.status != PfRecoveryJournalStatus::JournalMissing) {
        return existing.status;
    }
    return writeRecordUnlocked(directoryFd_, serializeRecord(sessionIdBytes));
}

PfRecoveryJournalStatus
PfRecoveryJournal::clearAfterVerifiedCleanup(const QString &sessionId) const {
    if (directoryFd_ < 0 || status_ != PfRecoveryJournalStatus::Ready)
        return status_;
    if (!privateDirectory(directoryFd_))
        return PfRecoveryJournalStatus::InvalidDirectory;
    QByteArray sessionIdBytes;
    if (!validSessionId(sessionId, &sessionIdBytes))
        return PfRecoveryJournalStatus::InvalidSessionId;
    auto guard = acquireGuard(directoryFd_);
    if (guard.status != PfRecoveryJournalStatus::Ready)
        return guard.status;
    const auto existing = readRecordUnlocked(directoryFd_);
    if (existing.status != PfRecoveryJournalStatus::JournalPresent)
        return existing.status;
    if (!existing.record || existing.record->sessionId != sessionId)
        return PfRecoveryJournalStatus::SessionConflict;
    if (unlinkat(directoryFd_, journalFileName, 0) < 0)
        return PfRecoveryJournalStatus::IoFailed;
    if (fsync(directoryFd_) < 0)
        return PfRecoveryJournalStatus::DurabilityUncertain;
    return PfRecoveryJournalStatus::Cleared;
}

QString PfRecoveryJournal::statusName(PfRecoveryJournalStatus status) {
    switch (status) {
    case PfRecoveryJournalStatus::Ready:
        return "ready";
    case PfRecoveryJournalStatus::InvalidDirectory:
        return "invalid_directory";
    case PfRecoveryJournalStatus::LockFailed:
        return "lock_failed";
    case PfRecoveryJournalStatus::JournalMissing:
        return "journal_missing";
    case PfRecoveryJournalStatus::JournalPresent:
        return "journal_present";
    case PfRecoveryJournalStatus::UnsafeJournal:
        return "unsafe_journal";
    case PfRecoveryJournalStatus::InvalidJournal:
        return "invalid_journal";
    case PfRecoveryJournalStatus::InvalidSessionId:
        return "invalid_session_id";
    case PfRecoveryJournalStatus::SessionConflict:
        return "session_conflict";
    case PfRecoveryJournalStatus::IoFailed:
        return "io_failed";
    case PfRecoveryJournalStatus::DurabilityUncertain:
        return "durability_uncertain";
    case PfRecoveryJournalStatus::Persisted:
        return "persisted";
    case PfRecoveryJournalStatus::Cleared:
        return "cleared";
    }
    return "unknown";
}

} // namespace interceptor
