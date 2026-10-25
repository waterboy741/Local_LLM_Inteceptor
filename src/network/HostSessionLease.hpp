#pragma once

#include <QString>

namespace interceptor {

enum class HostSessionLeaseStatus {
    Acquired,
    AlreadyHeld,
    InvalidDirectory,
    OpenFailed,
    UnsafeLockFile,
    LockFailed,
    Released,
    ReleaseFailed
};

class HostSessionLease final {
  public:
    static HostSessionLease acquire(int trustedDirectoryFd);

    HostSessionLease(const HostSessionLease &) = delete;
    HostSessionLease &operator=(const HostSessionLease &) = delete;
    HostSessionLease(HostSessionLease &&other) noexcept;
    HostSessionLease &operator=(HostSessionLease &&other) = delete;
    ~HostSessionLease();

    bool acquired() const noexcept;
    HostSessionLeaseStatus status() const noexcept;
    bool descriptorHasCloseOnExec() const noexcept;
    HostSessionLeaseStatus release() noexcept;

    static QString statusName(HostSessionLeaseStatus status);

  private:
    explicit HostSessionLease(HostSessionLeaseStatus status, int lockFd = -1) noexcept;

    HostSessionLeaseStatus status_;
    int lockFd_;
};

} // namespace interceptor
