#include "network/PfRecoveryJournal.hpp"

#include <QTemporaryDir>
#include <QtTest>

#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>

using namespace interceptor;
static_assert(!std::is_copy_constructible_v<PfRecoveryJournal>);
static_assert(!std::is_copy_assignable_v<PfRecoveryJournal>);
static_assert(std::is_nothrow_move_constructible_v<PfRecoveryJournal>);

namespace {
constexpr char journalName[] = "llm_interceptor.recovery.journal";

bool writeAll(int fd, const QByteArray &data) {
    qsizetype offset = 0;
    while (offset < data.size()) {
        const auto written = ::write(fd, data.constData() + offset,
                                     static_cast<size_t>(data.size() - offset));
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return false;
        offset += static_cast<qsizetype>(written);
    }
    return true;
}

bool writeRawJournal(int directoryFd, const QByteArray &bytes, mode_t mode = 0600) {
    const int fd = ::openat(directoryFd, journalName,
                            O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, mode);
    if (fd < 0)
        return false;
    const bool written = writeAll(fd, bytes);
    const bool closed = ::close(fd) == 0;
    if (::fchmodat(directoryFd, journalName, mode, 0) != 0)
        return false;
    return written && closed;
}

QByteArray readRawJournal(int directoryFd) {
    const int fd = ::openat(directoryFd, journalName, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return {};
    QByteArray bytes(513, Qt::Uninitialized);
    const auto count = ::read(fd, bytes.data(), static_cast<size_t>(bytes.size()));
    const bool closed = ::close(fd) == 0;
    if (count < 0 || !closed)
        return {};
    bytes.resize(static_cast<qsizetype>(count));
    return bytes;
}
} // namespace

class PrivateJournalDirectory {
  public:
    PrivateJournalDirectory() {
        if (!directory_.isValid())
            return;
        if (::chmod(directory_.path().toLocal8Bit().constData(), 0700) != 0)
            return;
        fd_ = ::open(directory_.path().toLocal8Bit().constData(),
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    }
    ~PrivateJournalDirectory() {
        if (fd_ >= 0)
            ::close(fd_);
    }
    bool valid() const { return directory_.isValid() && fd_ >= 0; }
    int fd() const { return fd_; }
    QString path() const { return directory_.path(); }
    void closeFd() {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

  private:
    QTemporaryDir directory_;
    int fd_ = -1;
};

class M6PfRecoveryJournalTests : public QObject {
    Q_OBJECT
  private slots:
    void persistReopenAndReadCrashLikeCleanupRecord() {
        PrivateJournalDirectory directory;
        QVERIFY(directory.valid());
        auto journal = PfRecoveryJournal::open(directory.fd());
        QVERIFY(journal.valid());
        QCOMPARE(journal.status(), PfRecoveryJournalStatus::Ready);
        QCOMPARE(journal.read().status, PfRecoveryJournalStatus::JournalMissing);

        QCOMPARE(journal.persistCleanupNeeded("recovery-a"),
                 PfRecoveryJournalStatus::Persisted);
        struct stat info {};
        QVERIFY(::fstatat(directory.fd(), journalName, &info, AT_SYMLINK_NOFOLLOW) == 0);
        QVERIFY(S_ISREG(info.st_mode));
        QCOMPARE(info.st_uid, ::geteuid());
        QCOMPARE(info.st_mode & 07777, mode_t(0600));
        QCOMPARE(info.st_nlink, nlink_t(1));

        auto reopened = PfRecoveryJournal::open(directory.fd());
        QVERIFY(reopened.valid());
        const auto read = reopened.read();
        QCOMPARE(read.status, PfRecoveryJournalStatus::JournalPresent);
        QVERIFY(read.record.has_value());
        QCOMPARE(read.record->sessionId, QString("recovery-a"));
        QCOMPARE(read.record->anchor, QString("llm_interceptor/recovery-a"));
        QCOMPARE(read.record->phase, QString("cleanup_needed"));

        const auto persistedBytes = readRawJournal(directory.fd());
        QVERIFY(!persistedBytes.isEmpty());
        QCOMPARE(reopened.persistCleanupNeeded("recovery-a"),
                 PfRecoveryJournalStatus::SessionConflict);
        QCOMPARE(reopened.persistCleanupNeeded("recovery-b"),
                 PfRecoveryJournalStatus::SessionConflict);
        QCOMPARE(readRawJournal(directory.fd()), persistedBytes);
        const auto preserved = reopened.read();
        QCOMPARE(preserved.status, PfRecoveryJournalStatus::JournalPresent);
        QCOMPARE(preserved.record->sessionId, QString("recovery-a"));
    }

    void invalidSessionIdsDoNotCreateOrReplaceJournal() {
        PrivateJournalDirectory directory;
        QVERIFY(directory.valid());
        auto journal = PfRecoveryJournal::open(directory.fd());
        for (const auto &sessionId : {QString{}, QString("."), QString("../bad"),
                                      QString("bad/id"), QString("bad token"),
                                      QString(49, 'x'), QString(65, 'x')}) {
            QCOMPARE(journal.persistCleanupNeeded(sessionId),
                     PfRecoveryJournalStatus::InvalidSessionId);
            QCOMPARE(journal.read().status, PfRecoveryJournalStatus::JournalMissing);
        }
    }

    void validSnapshotGrammarIdsPersistIncludingLeadingPunctuation() {
        PrivateJournalDirectory directory;
        QVERIFY(directory.valid());
        auto journal = PfRecoveryJournal::open(directory.fd());
        for (const auto &sessionId : {QString("_leading"), QString("-leading"), QString(48, 'x')}) {
            QCOMPARE(journal.persistCleanupNeeded(sessionId), PfRecoveryJournalStatus::Persisted);
            const auto read = journal.read();
            QCOMPARE(read.status, PfRecoveryJournalStatus::JournalPresent);
            QVERIFY(read.record.has_value());
            QCOMPARE(read.record->sessionId, sessionId);
            QCOMPARE(journal.clearAfterVerifiedCleanup(sessionId), PfRecoveryJournalStatus::Cleared);
        }
    }

    void concurrentGuardHolderCausesImmediateFailClosedResults() {
        PrivateJournalDirectory directory;
        QVERIFY(directory.valid());
        auto journal = PfRecoveryJournal::open(directory.fd());
        const int guardFd = ::openat(directory.fd(), "llm_interceptor.recovery.lock",
                                     O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
        QVERIFY(guardFd >= 0);
        QVERIFY(::flock(guardFd, LOCK_EX | LOCK_NB) == 0);

        QCOMPARE(journal.read().status, PfRecoveryJournalStatus::LockFailed);
        QCOMPARE(journal.persistCleanupNeeded("recovery-a"),
                 PfRecoveryJournalStatus::LockFailed);
        QCOMPARE(journal.read().status, PfRecoveryJournalStatus::LockFailed);
        QCOMPARE(readRawJournal(directory.fd()), QByteArray{});

        QVERIFY(::flock(guardFd, LOCK_UN) == 0);
        QCOMPARE(::close(guardFd), 0);
        QCOMPARE(journal.persistCleanupNeeded("recovery-a"), PfRecoveryJournalStatus::Persisted);
    }

    void journalOwnsDuplicatedDirectoryDescriptor() {
        PrivateJournalDirectory directory;
        QVERIFY(directory.valid());
        auto journal = PfRecoveryJournal::open(directory.fd());
        QVERIFY(journal.valid());
        directory.closeFd();
        QCOMPARE(journal.persistCleanupNeeded("owned-fd"), PfRecoveryJournalStatus::Persisted);
        const auto read = journal.read();
        QCOMPARE(read.status, PfRecoveryJournalStatus::JournalPresent);
        QVERIFY(read.record.has_value());
        QCOMPARE(read.record->sessionId, QString("owned-fd"));
    }

    void malformedTruncatedAndOversizedRecordsFailClosed() {
        const QList<QByteArray> invalidRecords = {
            QByteArray{},
            QByteArrayLiteral("llm-interceptor.pf-recovery.v1\n"),
            QByteArrayLiteral("schema=llm-interceptor.pf-recovery.v0\nsession_id=recovery-a\n"
                              "anchor=llm_interceptor/recovery-a\nphase=cleanup_needed\n"),
            QByteArrayLiteral("schema=llm-interceptor.pf-recovery.v1\nsession_id=recovery-a\n"
                              "anchor=llm_interceptor/wrong\nphase=cleanup_needed\n"),
            QByteArray(513, 'x')};
        for (const auto &bytes : invalidRecords) {
            PrivateJournalDirectory directory;
            QVERIFY(directory.valid());
            QVERIFY(writeRawJournal(directory.fd(), bytes));
            auto journal = PfRecoveryJournal::open(directory.fd());
            QVERIFY(journal.valid());
            const auto result = journal.read();
            QCOMPARE(result.status, PfRecoveryJournalStatus::InvalidJournal);
            QVERIFY(!result.record.has_value());
        }
    }

    void symlinkNonregularAndInsecureJournalEntriesAreRejected() {
        {
            PrivateJournalDirectory directory;
            QVERIFY(directory.valid());
            QVERIFY(::symlinkat("target", directory.fd(), journalName) == 0);
            auto journal = PfRecoveryJournal::open(directory.fd());
            QCOMPARE(journal.read().status, PfRecoveryJournalStatus::UnsafeJournal);
        }
        {
            PrivateJournalDirectory directory;
            QVERIFY(directory.valid());
            QVERIFY(::mkfifoat(directory.fd(), journalName, 0600) == 0);
            auto journal = PfRecoveryJournal::open(directory.fd());
            QCOMPARE(journal.read().status, PfRecoveryJournalStatus::UnsafeJournal);
        }
        {
            PrivateJournalDirectory directory;
            QVERIFY(directory.valid());
            QVERIFY(writeRawJournal(directory.fd(), QByteArrayLiteral("malformed"), 0644));
            auto journal = PfRecoveryJournal::open(directory.fd());
            QCOMPARE(journal.read().status, PfRecoveryJournalStatus::UnsafeJournal);
        }
    }

    void journalOwnedByAnotherUidIsRejectedWhenPrivileged() {
        if (::geteuid() != 0)
            QSKIP("Changing ownership requires root; valid-owner behavior is tested separately");
        PrivateJournalDirectory directory;
        QVERIFY(directory.valid());
        const QByteArray bytes =
            "schema=llm-interceptor.pf-recovery.v1\nsession_id=recovery-a\n"
            "anchor=llm_interceptor/recovery-a\nphase=cleanup_needed\n";
        const int file = ::openat(directory.fd(), journalName,
                                  O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
        QVERIFY(file >= 0);
        QVERIFY(writeAll(file, bytes));
        QVERIFY(::fchown(file, 1, static_cast<gid_t>(-1)) == 0);
        QVERIFY(::fchmod(file, 0600) == 0);
        QVERIFY(::close(file) == 0);

        auto journal = PfRecoveryJournal::open(directory.fd());
        QCOMPARE(journal.read().status, PfRecoveryJournalStatus::UnsafeJournal);
    }

    void persistDoesNotReplaceMalformedExistingRecord() {
        PrivateJournalDirectory directory;
        QVERIFY(directory.valid());
        const QByteArray malformed = QByteArrayLiteral("do not replace this record\n");
        QVERIFY(writeRawJournal(directory.fd(), malformed));
        auto journal = PfRecoveryJournal::open(directory.fd());

        QCOMPARE(journal.persistCleanupNeeded("recovery-a"),
                 PfRecoveryJournalStatus::InvalidJournal);
        const int file = ::openat(directory.fd(), journalName, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        QVERIFY(file >= 0);
        QByteArray actual(malformed.size(), Qt::Uninitialized);
        QCOMPARE(::read(file, actual.data(), static_cast<size_t>(actual.size())),
                 static_cast<ssize_t>(malformed.size()));
        QCOMPARE(::close(file), 0);
        QCOMPARE(actual, malformed);
    }

    void insecureDirectoryAndInvalidDescriptorAreRejected() {
        PrivateJournalDirectory directory;
        QVERIFY(directory.valid());
        QVERIFY(::fchmod(directory.fd(), 0755) == 0);
        auto insecure = PfRecoveryJournal::open(directory.fd());
        QVERIFY(!insecure.valid());
        QCOMPARE(insecure.status(), PfRecoveryJournalStatus::InvalidDirectory);

        auto invalidFd = PfRecoveryJournal::open(-1);
        QVERIFY(!invalidFd.valid());
        QCOMPARE(invalidFd.status(), PfRecoveryJournalStatus::InvalidDirectory);
    }

    void directoryModeChangeAfterOpenFailsClosedUntilRestored() {
        PrivateJournalDirectory directory;
        QVERIFY(directory.valid());
        auto journal = PfRecoveryJournal::open(directory.fd());
        QVERIFY(journal.valid());

        QVERIFY(::fchmod(directory.fd(), 0500) == 0);
        QVERIFY(!journal.valid());
        QCOMPARE(journal.read().status, PfRecoveryJournalStatus::InvalidDirectory);
        QCOMPARE(journal.persistCleanupNeeded("recovery-a"),
                 PfRecoveryJournalStatus::InvalidDirectory);
        QVERIFY(::fchmod(directory.fd(), 0700) == 0);
        QVERIFY(journal.valid());
        QCOMPARE(journal.read().status, PfRecoveryJournalStatus::JournalMissing);
    }

    void clearRequiresMatchingSessionAndRemovesOnlyAfterVerifiedCleanup() {
        PrivateJournalDirectory directory;
        QVERIFY(directory.valid());
        auto journal = PfRecoveryJournal::open(directory.fd());
        QCOMPARE(journal.persistCleanupNeeded("recovery-a"),
                 PfRecoveryJournalStatus::Persisted);
        QCOMPARE(journal.clearAfterVerifiedCleanup("recovery-b"),
                 PfRecoveryJournalStatus::SessionConflict);
        QCOMPARE(journal.read().status, PfRecoveryJournalStatus::JournalPresent);
        QCOMPARE(journal.clearAfterVerifiedCleanup("recovery-a"),
                 PfRecoveryJournalStatus::Cleared);
        QCOMPARE(journal.read().status, PfRecoveryJournalStatus::JournalMissing);
        struct stat info {};
        QCOMPARE(::fstatat(directory.fd(), journalName, &info, AT_SYMLINK_NOFOLLOW), -1);
        QCOMPARE(errno, ENOENT);
        QCOMPARE(journal.persistCleanupNeeded("recovery-b"),
                 PfRecoveryJournalStatus::Persisted);
        const auto nextRecord = journal.read();
        QCOMPARE(nextRecord.status, PfRecoveryJournalStatus::JournalPresent);
        QVERIFY(nextRecord.record.has_value());
        QCOMPARE(nextRecord.record->sessionId, QString("recovery-b"));
    }

    void clearFailurePreservesPendingRecord() {
        if (::geteuid() == 0)
            QSKIP("Permission-based clear failure cannot be exercised as root");
        PrivateJournalDirectory directory;
        QVERIFY(directory.valid());
        auto journal = PfRecoveryJournal::open(directory.fd());
        QCOMPARE(journal.persistCleanupNeeded("recovery-a"),
                 PfRecoveryJournalStatus::Persisted);

        QVERIFY(::fchmod(directory.fd(), 0500) == 0);
        const auto clearStatus = journal.clearAfterVerifiedCleanup("recovery-a");
        QVERIFY(clearStatus != PfRecoveryJournalStatus::Cleared);
        QVERIFY(::fchmod(directory.fd(), 0700) == 0);
        const auto read = journal.read();
        QCOMPARE(read.status, PfRecoveryJournalStatus::JournalPresent);
        QVERIFY(read.record.has_value());
        QCOMPARE(read.record->sessionId, QString("recovery-a"));
    }
};

QTEST_GUILESS_MAIN(M6PfRecoveryJournalTests)
#include "M6PfRecoveryJournalTests.moc"
