#include "network/HostSessionLease.hpp"

#include <QTemporaryDir>
#include <QtTest>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <type_traits>
#include <unistd.h>

using namespace interceptor;
static_assert(!std::is_copy_constructible_v<HostSessionLease>);
static_assert(!std::is_copy_assignable_v<HostSessionLease>);
static_assert(std::is_nothrow_move_constructible_v<HostSessionLease>);

class PrivateTempDirectory {
  public:
    PrivateTempDirectory() {
        if (!directory_.isValid())
            return;
        if (::chmod(directory_.path().toLocal8Bit().constData(), 0700) != 0)
            return;
        descriptor_ = ::open(directory_.path().toLocal8Bit().constData(),
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    }
    ~PrivateTempDirectory() {
        if (descriptor_ >= 0)
            ::close(descriptor_);
    }
    bool valid() const { return directory_.isValid() && descriptor_ >= 0; }
    int fd() const { return descriptor_; }
    QString path() const { return directory_.path(); }

  private:
    QTemporaryDir directory_;
    int descriptor_ = -1;
};

class M6HostSessionLeaseTests : public QObject {
    Q_OBJECT
  private slots:
    void independentOpensAreExclusiveAndReleaseAllowsReacquisition() {
        PrivateTempDirectory directory;
        QVERIFY(directory.valid());

        auto first = HostSessionLease::acquire(directory.fd());
        QVERIFY(first.acquired());
        QCOMPARE(first.status(), HostSessionLeaseStatus::Acquired);
        QVERIFY(first.descriptorHasCloseOnExec());

        auto second = HostSessionLease::acquire(directory.fd());
        QVERIFY(!second.acquired());
        QCOMPARE(second.status(), HostSessionLeaseStatus::AlreadyHeld);

        QCOMPARE(first.release(), HostSessionLeaseStatus::Released);
        QVERIFY(!first.acquired());
        QCOMPARE(first.status(), HostSessionLeaseStatus::Released);

        auto third = HostSessionLease::acquire(directory.fd());
        QVERIFY(third.acquired());
        QCOMPARE(third.status(), HostSessionLeaseStatus::Acquired);
        QCOMPARE(third.release(), HostSessionLeaseStatus::Released);

        struct stat info {};
        QVERIFY(::fstatat(directory.fd(), "llm_interceptor.session.lock", &info,
                          AT_SYMLINK_NOFOLLOW) == 0);
        QVERIFY(S_ISREG(info.st_mode));
        QCOMPARE(info.st_uid, ::geteuid());
        QCOMPARE(info.st_nlink, nlink_t(1));
        QCOMPARE(info.st_mode & 07777, mode_t(0600));
    }

    void independentProcessCannotAcquireUntilOwnerReleases() {
        PrivateTempDirectory directory;
        QVERIFY(directory.valid());
        int statusPipe[2] = {-1, -1};
        int releasePipe[2] = {-1, -1};
        QCOMPARE(::pipe(statusPipe), 0);
        QCOMPARE(::pipe(releasePipe), 0);

        const QByteArray path = directory.path().toLocal8Bit();
        const pid_t child = ::fork();
        QVERIFY(child >= 0);
        if (child == 0) {
            ::close(statusPipe[0]);
            ::close(releasePipe[1]);
            const int childDirectory = ::open(path.constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (childDirectory < 0)
                _exit(2);
            auto lease = HostSessionLease::acquire(childDirectory);
            const char acquired = lease.acquired() ? '1' : '0';
            if (::write(statusPipe[1], &acquired, 1) != 1)
                _exit(3);
            if (acquired != '1')
                _exit(4);
            char release = 0;
            if (::read(releasePipe[0], &release, 1) != 1 || release != 'x')
                _exit(5);
            const auto released = lease.release();
            ::close(childDirectory);
            _exit(released == HostSessionLeaseStatus::Released ? 0 : 6);
        }

        ::close(statusPipe[1]);
        statusPipe[1] = -1;
        ::close(releasePipe[0]);
        releasePipe[0] = -1;
        char acquired = 0;
        QCOMPARE(::read(statusPipe[0], &acquired, 1), ssize_t(1));
        QCOMPARE(acquired, '1');

        auto denied = HostSessionLease::acquire(directory.fd());
        QVERIFY(!denied.acquired());
        QCOMPARE(denied.status(), HostSessionLeaseStatus::AlreadyHeld);

        const char release = 'x';
        QCOMPARE(::write(releasePipe[1], &release, 1), ssize_t(1));
        int childStatus = 0;
        QCOMPARE(::waitpid(child, &childStatus, 0), child);
        QVERIFY(WIFEXITED(childStatus));
        QCOMPARE(WEXITSTATUS(childStatus), 0);
        ::close(statusPipe[0]);
        ::close(releasePipe[1]);

        auto reacquired = HostSessionLease::acquire(directory.fd());
        QVERIFY(reacquired.acquired());
    }

    void destructorAndMovePreserveSingleLockOwnership() {
        PrivateTempDirectory directory;
        QVERIFY(directory.valid());

        {
            auto lease = HostSessionLease::acquire(directory.fd());
            QVERIFY(lease.acquired());
            auto moved = std::move(lease);
            QVERIFY(!lease.acquired());
            QCOMPARE(lease.status(), HostSessionLeaseStatus::Released);
            QVERIFY(moved.acquired());
            auto blocked = HostSessionLease::acquire(directory.fd());
            QCOMPARE(blocked.status(), HostSessionLeaseStatus::AlreadyHeld);
        }

        auto reacquired = HostSessionLease::acquire(directory.fd());
        QVERIFY(reacquired.acquired());
    }

    void insecureDirectoryIsRejected() {
        PrivateTempDirectory directory;
        QVERIFY(directory.valid());
        QVERIFY(::fchmod(directory.fd(), 0755) == 0);

        auto lease = HostSessionLease::acquire(directory.fd());
        QVERIFY(!lease.acquired());
        QCOMPARE(lease.status(), HostSessionLeaseStatus::InvalidDirectory);
    }

    void symlinkLockFileIsRejectedWithoutFollowingTarget() {
        PrivateTempDirectory directory;
        QVERIFY(directory.valid());
        QVERIFY(::symlinkat("target", directory.fd(), "llm_interceptor.session.lock") == 0);

        auto lease = HostSessionLease::acquire(directory.fd());
        QVERIFY(!lease.acquired());
        QCOMPARE(lease.status(), HostSessionLeaseStatus::UnsafeLockFile);
        struct stat info {};
        QVERIFY(::fstatat(directory.fd(), "llm_interceptor.session.lock", &info,
                          AT_SYMLINK_NOFOLLOW) == 0);
        QVERIFY(S_ISLNK(info.st_mode));
    }

    void nonregularAndInsecureLockFilesAreRejected() {
        {
            PrivateTempDirectory directory;
            QVERIFY(directory.valid());
            QVERIFY(::mkfifoat(directory.fd(), "llm_interceptor.session.lock", 0600) == 0);
            auto lease = HostSessionLease::acquire(directory.fd());
            QVERIFY(!lease.acquired());
            QCOMPARE(lease.status(), HostSessionLeaseStatus::UnsafeLockFile);
        }
        {
            PrivateTempDirectory directory;
            QVERIFY(directory.valid());
            const int file = ::openat(directory.fd(), "llm_interceptor.session.lock",
                                      O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0644);
            QVERIFY(file >= 0);
            QVERIFY(::close(file) == 0);
            auto lease = HostSessionLease::acquire(directory.fd());
            QVERIFY(!lease.acquired());
            QCOMPARE(lease.status(), HostSessionLeaseStatus::UnsafeLockFile);
        }
    }

    void hardLinkedLockFileIsRejected() {
        PrivateTempDirectory directory;
        QVERIFY(directory.valid());
        const int file = ::openat(directory.fd(), "llm_interceptor.session.lock",
                                  O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
        QVERIFY(file >= 0);
        QVERIFY(::close(file) == 0);
        QVERIFY(::linkat(directory.fd(), "llm_interceptor.session.lock", directory.fd(),
                         "second-link", 0) == 0);

        auto lease = HostSessionLease::acquire(directory.fd());
        QVERIFY(!lease.acquired());
        QCOMPARE(lease.status(), HostSessionLeaseStatus::UnsafeLockFile);
    }
};

QTEST_GUILESS_MAIN(M6HostSessionLeaseTests)
#include "M6HostSessionLeaseTests.moc"
