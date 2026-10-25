#include "HostSessionLease.hpp"

#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace interceptor {
namespace {
constexpr char lockFileName[] = "llm_interceptor.session.lock";
constexpr mode_t privatePermissions = 0700;

bool privateDirectory(int directoryFd) {
    struct stat info{};
    return fstat(directoryFd, &info) == 0 && S_ISDIR(info.st_mode) && info.st_uid == geteuid() &&
           (info.st_mode & 07777) == privatePermissions;
}

bool safeLockFile(int lockFd) {
    struct stat info{};
    return fstat(lockFd, &info) == 0 && S_ISREG(info.st_mode) && info.st_uid == geteuid() &&
           (info.st_mode & 07777) == 0600 && info.st_nlink == 1;
}

} // namespace

HostSessionLease::HostSessionLease(HostSessionLeaseStatus status, int lockFd) noexcept
    : status_(status), lockFd_(lockFd) {}

HostSessionLease HostSessionLease::acquire(int trustedDirectoryFd) {
    if (!privateDirectory(trustedDirectoryFd))
        return HostSessionLease(HostSessionLeaseStatus::InvalidDirectory);

    const int lockFd = openat(trustedDirectoryFd, lockFileName,
                              O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (lockFd < 0) {
        if (errno == ELOOP || errno == EISDIR)
            return HostSessionLease(HostSessionLeaseStatus::UnsafeLockFile);
        return HostSessionLease(HostSessionLeaseStatus::OpenFailed);
    }

    if (!safeLockFile(lockFd)) {
        close(lockFd);
        return HostSessionLease(HostSessionLeaseStatus::UnsafeLockFile);
    }

    int lockResult;
    do {
        lockResult = flock(lockFd, LOCK_EX | LOCK_NB);
    } while (lockResult < 0 && errno == EINTR);
    if (lockResult < 0) {
        const auto failure = (errno == EWOULDBLOCK || errno == EAGAIN)
                                 ? HostSessionLeaseStatus::AlreadyHeld
                                 : HostSessionLeaseStatus::LockFailed;
        close(lockFd);
        return HostSessionLease(failure);
    }

    // Recheck after acquiring the lock so validation and ownership refer to the locked inode.
    if (!safeLockFile(lockFd)) {
        flock(lockFd, LOCK_UN);
        close(lockFd);
        return HostSessionLease(HostSessionLeaseStatus::UnsafeLockFile);
    }
    return HostSessionLease(HostSessionLeaseStatus::Acquired, lockFd);
}

HostSessionLease::HostSessionLease(HostSessionLease &&other) noexcept
    : status_(other.status_), lockFd_(other.lockFd_) {
    other.status_ = HostSessionLeaseStatus::Released;
    other.lockFd_ = -1;
}

HostSessionLease::~HostSessionLease() { release(); }

bool HostSessionLease::acquired() const noexcept {
    return lockFd_ >= 0 && status_ == HostSessionLeaseStatus::Acquired;
}

HostSessionLeaseStatus HostSessionLease::status() const noexcept { return status_; }

bool HostSessionLease::descriptorHasCloseOnExec() const noexcept {
    if (!acquired())
        return false;
    const int flags = fcntl(lockFd_, F_GETFD);
    return flags >= 0 && (flags & FD_CLOEXEC) != 0;
}

HostSessionLeaseStatus HostSessionLease::release() noexcept {
    if (lockFd_ < 0)
        return status_;

    bool released = true;
    if (flock(lockFd_, LOCK_UN) < 0)
        released = false;
    if (close(lockFd_) < 0)
        released = false;
    lockFd_ = -1;
    status_ = released ? HostSessionLeaseStatus::Released : HostSessionLeaseStatus::ReleaseFailed;
    return status_;
}

QString HostSessionLease::statusName(HostSessionLeaseStatus status) {
    switch (status) {
    case HostSessionLeaseStatus::Acquired:
        return "acquired";
    case HostSessionLeaseStatus::AlreadyHeld:
        return "already_held";
    case HostSessionLeaseStatus::InvalidDirectory:
        return "invalid_directory";
    case HostSessionLeaseStatus::OpenFailed:
        return "open_failed";
    case HostSessionLeaseStatus::UnsafeLockFile:
        return "unsafe_lock_file";
    case HostSessionLeaseStatus::LockFailed:
        return "lock_failed";
    case HostSessionLeaseStatus::Released:
        return "released";
    case HostSessionLeaseStatus::ReleaseFailed:
        return "release_failed";
    }
    return "unknown";
}

} // namespace interceptor
