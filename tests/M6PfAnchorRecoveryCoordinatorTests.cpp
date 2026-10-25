#include "network/PfAnchorRecoveryCoordinator.hpp"

#include <QTemporaryDir>
#include <QtTest>

#include <fcntl.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

using namespace interceptor;

class CoordinatorTempDirectory {
  public:
    CoordinatorTempDirectory() {
        if (!directory_.isValid())
            return;
        if (::chmod(directory_.path().toLocal8Bit().constData(), 0700) != 0)
            return;
        fd_ =
            ::open(directory_.path().toLocal8Bit().constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    }
    ~CoordinatorTempDirectory() {
        if (fd_ >= 0)
            ::close(fd_);
    }
    bool valid() const { return directory_.isValid() && fd_ >= 0; }
    int fd() const { return fd_; }

  private:
    QTemporaryDir directory_;
    int fd_ = -1;
};

class CoordinatorFakeAuthorization final : public PfAnchorAuthorization {
  public:
    QStringList calls;
    bool root = true;
    bool enabled = true;
    bool leaseValid = true;
    bool attachmentValid = true;
    bool ownershipValid = true;

    bool effectiveUserIsRoot() override {
        calls << "root";
        return root;
    }
    bool pfEnabled() override {
        calls << "pf_enabled";
        return enabled;
    }
    bool verifySessionLease(const SessionSnapshot &, const QString &) override {
        calls << "lease";
        return leaseValid;
    }
    bool verifyActiveAttachment(const SessionSnapshot &) override {
        calls << "attachment";
        return attachmentValid;
    }
    bool verifyAnchorOwnership(const SessionSnapshot &, const QString &,
                               PfAnchorOperation) override {
        calls << "ownership";
        return ownershipValid;
    }
};

class CoordinatorFakeRunner final : public PfAnchorCommandRunner {
  public:
    QVector<PfAnchorCommandResult> results;
    QVector<PfAnchorOperation> operations;
    std::function<void(const PfAnchorCommand &)> beforeExecute;

    PfAnchorCommandResult execute(const PfAnchorCommand &command, int, qsizetype) override {
        operations.append(command.operation());
        if (beforeExecute)
            beforeExecute(command);
        if (results.isEmpty())
            return {PfAnchorCommandStatus::Completed, 0, true, true};
        const auto result = results.front();
        results.pop_front();
        return result;
    }
};

class CoordinatorFakeVerifier final : public PfAnchorCleanupVerifier {
  public:
    PfAnchorCleanupVerification next = PfAnchorCleanupVerification::Empty;
    int calls = 0;
    QStringList *events = nullptr;
    std::function<void()> duringVerify;
    bool shouldThrow = false;

    PfAnchorCleanupVerification verifyOwnedAnchorEmpty(const SessionSnapshot &) override {
        ++calls;
        if (events)
            events->append("verify");
        if (duringVerify)
            duringVerify();
        if (shouldThrow)
            throw std::runtime_error("synthetic verifier failure");
        return next;
    }
};

class M6PfAnchorRecoveryCoordinatorTests : public QObject {
    Q_OBJECT
  private:
    static SessionConfig validConfig() {
        return {"en0", "192.0.2.10", "192.0.2.30", 18081, {"/api/generate"}, false};
    }
    static NetworkFacts validFacts() {
        NetworkFacts facts;
        facts.interfaceName = "en0";
        facts.researchIp = "192.0.2.20";
        facts.researchMac = "02:00:00:00:00:20";
        facts.clientMac = "02:00:00:00:00:10";
        facts.serverMac = "02:00:00:00:00:30";
        facts.proxyServerIp = "192.0.2.30";
        facts.proxyServerPort = 18081;
        facts.proxyListenPort = 11434;
        facts.interfaceUp = facts.sameLink = facts.anchorAttached = facts.proxyReady =
            facts.authorized = true;
        return facts;
    }
    static SessionSnapshot snapshot(const QString &id) {
        const auto created = SessionSnapshot::create(validConfig(), validFacts(), 11434, id);
        if (!created)
            qFatal("Unable to create synthetic coordinator snapshot");
        return *created;
    }

  private slots:
    void installWritesAheadOfRunnerAndKeepsPendingForEveryCommandOutcome() {
        const QList<PfAnchorCommandResult> outcomes = {
            {PfAnchorCommandStatus::Completed, 0, true, true},
            {PfAnchorCommandStatus::Failed, -1, true, true},
            {PfAnchorCommandStatus::TimedOut, -1, true, true},
            {PfAnchorCommandStatus::Failed, -1, false, true}};
        for (const auto &outcome : outcomes) {
            CoordinatorTempDirectory directory;
            QVERIFY(directory.valid());
            auto journal = PfRecoveryJournal::open(directory.fd());
            QVERIFY(journal.valid());
            CoordinatorFakeAuthorization authorization;
            CoordinatorFakeRunner runner;
            runner.results.append(outcome);
            PfAnchorOperations operations(authorization, runner);
            CoordinatorFakeVerifier verifier;
            PfAnchorRecoveryCoordinator coordinator(operations, journal, verifier);
            const auto session = snapshot("coordinator-a");

            bool recordVisibleBeforeCommand = false;
            runner.beforeExecute = [&](const PfAnchorCommand &) {
                const auto read = journal.read();
                recordVisibleBeforeCommand =
                    read.status == PfRecoveryJournalStatus::JournalPresent && read.record &&
                    read.record->sessionId == "coordinator-a" &&
                    read.record->phase == "cleanup_needed";
            };
            const auto result = coordinator.install(session, "lease-token");
            QVERIFY(recordVisibleBeforeCommand);
            QCOMPARE(runner.operations.size(), 1);
            QCOMPARE(runner.operations.front(), PfAnchorOperation::Install);
            QVERIFY(verifier.calls == 0);
            const auto persisted = journal.read();
            QCOMPARE(persisted.status, PfRecoveryJournalStatus::JournalPresent);
            QVERIFY(persisted.record.has_value());
            QCOMPARE(persisted.record->sessionId, QString("coordinator-a"));
            QVERIFY(result.cleanupPending);
            if (outcome.status == PfAnchorCommandStatus::Completed && outcome.exitCode == 0) {
                QVERIFY(result.success);
                QCOMPARE(result.statusCode, QString("installed_cleanup_pending"));
            } else {
                QVERIFY(!result.success);
                QCOMPARE(result.statusCode, QString("install_failed_cleanup_pending"));
                if (!outcome.started)
                    QVERIFY(!result.operationMayHaveApplied);
            }
        }
    }

    void installNeverCallsPfWhenJournalIsBlockedOrUntrusted() {
        {
            CoordinatorTempDirectory directory;
            QVERIFY(directory.valid());
            auto journal = PfRecoveryJournal::open(directory.fd());
            QVERIFY(journal.valid());
            QCOMPARE(journal.persistCleanupNeeded("another-session"),
                     PfRecoveryJournalStatus::Persisted);
            CoordinatorFakeAuthorization authorization;
            CoordinatorFakeRunner runner;
            PfAnchorOperations operations(authorization, runner);
            CoordinatorFakeVerifier verifier;
            PfAnchorRecoveryCoordinator coordinator(operations, journal, verifier);
            const auto result = coordinator.install(snapshot("coordinator-a"), "lease-token");
            QVERIFY(!result.success);
            QVERIFY(result.cleanupPending);
            QCOMPARE(result.statusCode, QString("journal_not_durable"));
            QCOMPARE(result.journalStatus, PfRecoveryJournalStatus::SessionConflict);
            QVERIFY(runner.operations.isEmpty());
            QVERIFY(authorization.calls.isEmpty());
            QCOMPARE(journal.read().record->sessionId, QString("another-session"));
        }
        {
            CoordinatorTempDirectory directory;
            QVERIFY(directory.valid());
            const int invalid = ::openat(directory.fd(), "llm_interceptor.recovery.journal",
                                         O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
            QVERIFY(invalid >= 0);
            const QByteArray bytes("malformed\n");
            QCOMPARE(::write(invalid, bytes.constData(), static_cast<size_t>(bytes.size())),
                     static_cast<ssize_t>(bytes.size()));
            QCOMPARE(::close(invalid), 0);
            auto journal = PfRecoveryJournal::open(directory.fd());
            CoordinatorFakeAuthorization authorization;
            CoordinatorFakeRunner runner;
            PfAnchorOperations operations(authorization, runner);
            CoordinatorFakeVerifier verifier;
            PfAnchorRecoveryCoordinator coordinator(operations, journal, verifier);
            const auto result = coordinator.install(snapshot("coordinator-a"), "lease-token");
            QVERIFY(!result.success);
            QVERIFY(result.cleanupPending);
            QCOMPARE(result.journalStatus, PfRecoveryJournalStatus::InvalidJournal);
            QVERIFY(runner.operations.isEmpty());
            QVERIFY(authorization.calls.isEmpty());
        }
        {
            CoordinatorTempDirectory directory;
            QVERIFY(directory.valid());
            QVERIFY(::symlinkat("target", directory.fd(), "llm_interceptor.recovery.journal") == 0);
            auto journal = PfRecoveryJournal::open(directory.fd());
            CoordinatorFakeAuthorization authorization;
            CoordinatorFakeRunner runner;
            PfAnchorOperations operations(authorization, runner);
            CoordinatorFakeVerifier verifier;
            PfAnchorRecoveryCoordinator coordinator(operations, journal, verifier);
            const auto result = coordinator.install(snapshot("coordinator-a"), "lease-token");
            QVERIFY(!result.success);
            QVERIFY(result.cleanupPending);
            QCOMPARE(result.journalStatus, PfRecoveryJournalStatus::UnsafeJournal);
            QVERIFY(runner.operations.isEmpty());
            QVERIFY(authorization.calls.isEmpty());
        }
    }

    void cleanupChecksExactSessionThenRemoveVerifyAndOnlyThenClear() {
        CoordinatorTempDirectory directory;
        QVERIFY(directory.valid());
        auto journal = PfRecoveryJournal::open(directory.fd());
        QVERIFY(journal.valid());
        QCOMPARE(journal.persistCleanupNeeded("coordinator-a"), PfRecoveryJournalStatus::Persisted);
        CoordinatorFakeAuthorization authorization;
        CoordinatorFakeRunner runner;
        PfAnchorOperations operations(authorization, runner);
        CoordinatorFakeVerifier verifier;
        QStringList events;
        verifier.events = &events;
        runner.beforeExecute = [&](const PfAnchorCommand &) { events.append("remove"); };
        PfAnchorRecoveryCoordinator coordinator(operations, journal, verifier);

        auto mismatch = coordinator.cleanup(snapshot("coordinator-b"), "lease-token");
        QVERIFY(!mismatch.success);
        QVERIFY(mismatch.cleanupPending);
        QCOMPARE(mismatch.statusCode, QString("cleanup_journal_mismatch"));
        QVERIFY(runner.operations.isEmpty());
        QCOMPARE(verifier.calls, 0);

        runner.results.append({PfAnchorCommandStatus::Failed, -1, true, true});
        auto removeFailed = coordinator.cleanup(snapshot("coordinator-a"), "lease-token");
        QVERIFY(!removeFailed.success);
        QVERIFY(removeFailed.cleanupPending);
        QCOMPARE(removeFailed.statusCode, QString("cleanup_remove_failed_pending"));
        QCOMPARE(verifier.calls, 0);
        QCOMPARE(journal.read().status, PfRecoveryJournalStatus::JournalPresent);

        verifier.next = PfAnchorCleanupVerification::NotEmpty;
        auto remains = coordinator.cleanup(snapshot("coordinator-a"), "lease-token");
        QVERIFY(!remains.success);
        QVERIFY(remains.cleanupPending);
        QCOMPARE(remains.statusCode, QString("cleanup_anchor_not_empty"));
        QCOMPARE(remains.verification, PfAnchorCleanupVerification::NotEmpty);
        QCOMPARE(journal.read().status, PfRecoveryJournalStatus::JournalPresent);

        verifier.shouldThrow = true;
        auto verifierThrew = coordinator.cleanup(snapshot("coordinator-a"), "lease-token");
        QVERIFY(!verifierThrew.success);
        QVERIFY(verifierThrew.cleanupPending);
        QCOMPARE(verifierThrew.statusCode, QString("cleanup_anchor_unverified"));
        QCOMPARE(verifierThrew.verification, PfAnchorCleanupVerification::Unknown);
        QCOMPARE(journal.read().status, PfRecoveryJournalStatus::JournalPresent);
        verifier.shouldThrow = false;

        verifier.next = PfAnchorCleanupVerification::Unknown;
        auto unknown = coordinator.cleanup(snapshot("coordinator-a"), "lease-token");
        QVERIFY(!unknown.success);
        QVERIFY(unknown.cleanupPending);
        QCOMPARE(unknown.statusCode, QString("cleanup_anchor_unverified"));
        QCOMPARE(journal.read().status, PfRecoveryJournalStatus::JournalPresent);

        verifier.next = PfAnchorCleanupVerification::Empty;
        const int verifyCallsBefore = verifier.calls;
        auto complete = coordinator.cleanup(snapshot("coordinator-a"), "lease-token");
        QVERIFY(complete.success);
        QVERIFY(!complete.cleanupPending);
        QCOMPARE(complete.statusCode, QString("cleanup_complete"));
        QCOMPARE(complete.verification, PfAnchorCleanupVerification::Empty);
        QCOMPARE(verifier.calls, verifyCallsBefore + 1);
        QCOMPARE(journal.read().status, PfRecoveryJournalStatus::JournalMissing);
        QVERIFY(events.indexOf("remove") < events.indexOf("verify"));
        QVERIFY(events.count("remove") >= 3);
    }

    void cleanupWithoutJournalDoesNotRunRemoveOrVerifier() {
        CoordinatorTempDirectory directory;
        QVERIFY(directory.valid());
        auto journal = PfRecoveryJournal::open(directory.fd());
        CoordinatorFakeAuthorization authorization;
        CoordinatorFakeRunner runner;
        PfAnchorOperations operations(authorization, runner);
        CoordinatorFakeVerifier verifier;
        PfAnchorRecoveryCoordinator coordinator(operations, journal, verifier);

        const auto result = coordinator.cleanup(snapshot("coordinator-a"), "lease-token");
        QVERIFY(!result.success);
        QVERIFY(result.cleanupPending);
        QCOMPARE(result.statusCode, QString("cleanup_journal_missing"));
        QCOMPARE(result.journalStatus, PfRecoveryJournalStatus::JournalMissing);
        QVERIFY(runner.operations.isEmpty());
        QVERIFY(authorization.calls.isEmpty());
        QCOMPARE(verifier.calls, 0);
    }

    void pendingJournalSurvivesClearFailureAndCleanupCanRetry() {
        CoordinatorTempDirectory directory;
        QVERIFY(directory.valid());
        auto journal = PfRecoveryJournal::open(directory.fd());
        QCOMPARE(journal.persistCleanupNeeded("coordinator-a"), PfRecoveryJournalStatus::Persisted);
        CoordinatorFakeAuthorization authorization;
        CoordinatorFakeRunner runner;
        PfAnchorOperations operations(authorization, runner);
        CoordinatorFakeVerifier verifier;
        PfAnchorRecoveryCoordinator coordinator(operations, journal, verifier);
        verifier.duringVerify = [&] { QVERIFY(::fchmod(directory.fd(), 0500) == 0); };

        const auto clearFailure = coordinator.cleanup(snapshot("coordinator-a"), "lease-token");
        QVERIFY(!clearFailure.success);
        QVERIFY(clearFailure.cleanupPending);
        QCOMPARE(clearFailure.statusCode, QString("cleanup_journal_clear_uncertain"));
        QCOMPARE(clearFailure.verification, PfAnchorCleanupVerification::Empty);
        QCOMPARE(runner.operations.size(), 1);
        QCOMPARE(verifier.calls, 1);

        QVERIFY(::fchmod(directory.fd(), 0700) == 0);
        QCOMPARE(journal.read().status, PfRecoveryJournalStatus::JournalPresent);
        verifier.duringVerify = {};
        const auto retry = coordinator.cleanup(snapshot("coordinator-a"), "lease-token");
        QVERIFY(retry.success);
        QCOMPARE(retry.statusCode, QString("cleanup_complete"));
        QCOMPARE(journal.read().status, PfRecoveryJournalStatus::JournalMissing);
        QCOMPARE(runner.operations.size(), 2);
        QCOMPARE(verifier.calls, 2);
    }
};

QTEST_GUILESS_MAIN(M6PfAnchorRecoveryCoordinatorTests)
#include "M6PfAnchorRecoveryCoordinatorTests.moc"
