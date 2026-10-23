#include "network/PfAnchorOperations.hpp"
#include "network/PfAnchorQProcessRunner.hpp"

#include <QThread>
#include <QtTest>
#include <limits>
#include <memory>

using namespace interceptor;

class FakeAuthorization final : public PfAnchorAuthorization {
  public:
    bool effectiveUserIsRoot() override { return true; }
    bool pfEnabled() override { return true; }
    bool verifySessionLease(const SessionSnapshot &, const QString &) override { return true; }
    bool verifyActiveAttachment(const SessionSnapshot &) override { return true; }
    bool verifyAnchorOwnership(const SessionSnapshot &, const QString &,
                               PfAnchorOperation) override {
        return true;
    }
};

struct FakeChildState {
    bool startSucceeds = true;
    bool startedDespiteStartFailure = false;
    bool processStarted = false;
    bool running = false;
    bool finished = false;
    bool killed = false;
    bool reaped = false;
    bool writeClosed = false;
    bool holdOpen = false;
    bool waitForBytes = true;
    bool abnormalExit = false;
    bool failAfterPartialWrite = false;
    qint64 maximumWriteSize = std::numeric_limits<qint64>::max();
    int writeCalls = 0;
    int code = 0;
    int startTimeoutMs = 0;
    int finishTimeoutMs = 0;
    int readyReadWaitCalls = 0;
    QByteArray input;
    QByteArray stdoutBytes;
    QByteArray stderrBytes;
    QVector<qint64> stdoutReadLimits;
    QVector<qint64> stderrReadLimits;
    qsizetype stdoutBytesRead = 0;
    qsizetype stderrBytesRead = 0;
};

class FakeChildProcess final : public PfAnchorChildProcess {
  public:
    explicit FakeChildProcess(std::shared_ptr<FakeChildState> state) : state_(std::move(state)) {}

    bool start(int timeoutMs) override {
        state_->startTimeoutMs = timeoutMs;
        state_->processStarted = state_->startSucceeds || state_->startedDespiteStartFailure;
        state_->running = state_->processStarted;
        return state_->startSucceeds;
    }
    bool started() const override { return state_->processStarted; }
    qint64 write(const char *data, qint64 length) override {
        ++state_->writeCalls;
        if (state_->failAfterPartialWrite && state_->writeCalls > 1)
            return -1;
        const auto count = qMin(length, state_->maximumWriteSize);
        state_->input.append(data, static_cast<qsizetype>(count));
        return count;
    }
    qint64 bytesToWrite() const override { return 0; }
    bool waitForBytesWritten(int) override { return state_->waitForBytes; }
    void closeWriteChannel() override { state_->writeClosed = true; }
    bool waitForReadyRead(int timeoutMs) override {
        ++state_->readyReadWaitCalls;
        if (state_->holdOpen) {
            QThread::msleep(static_cast<unsigned long>(timeoutMs));
            return false;
        }
        state_->running = false;
        state_->finished = true;
        return true;
    }
    QByteArray readStandardOutput(qint64 maximumBytes) override {
        state_->stdoutReadLimits.append(maximumBytes);
        auto bytes = take(&state_->stdoutBytes, maximumBytes);
        state_->stdoutBytesRead += bytes.size();
        return bytes;
    }
    QByteArray readStandardError(qint64 maximumBytes) override {
        state_->stderrReadLimits.append(maximumBytes);
        auto bytes = take(&state_->stderrBytes, maximumBytes);
        state_->stderrBytesRead += bytes.size();
        return bytes;
    }
    bool isRunning() const override { return state_->running; }
    bool normalExit() const override { return !state_->abnormalExit; }
    int exitCode() const override { return state_->code; }
    bool failed() const override { return false; }
    void kill() override {
        state_->killed = true;
        state_->running = false;
    }
    bool waitForFinished(int timeoutMs) override {
        state_->finishTimeoutMs = timeoutMs;
        state_->running = false;
        state_->finished = true;
        state_->reaped = true;
        return true;
    }

  private:
    static QByteArray take(QByteArray *bytes, qint64 maximumBytes) {
        const auto count = qMin<qsizetype>(bytes->size(), static_cast<qsizetype>(maximumBytes));
        const auto result = bytes->left(count);
        bytes->remove(0, count);
        return result;
    }

    std::shared_ptr<FakeChildState> state_;
};

class FakeChildFactory final : public PfAnchorChildProcessFactory {
  public:
    std::shared_ptr<FakeChildState> state = std::make_shared<FakeChildState>();
    QString program;
    QStringList arguments;
    QByteArray standardInput;
    PfAnchorOperation operation = PfAnchorOperation::Install;
    QString anchor;
    int createCalls = 0;

    std::unique_ptr<PfAnchorChildProcess> create(const PfAnchorCommand &command) override {
        ++createCalls;
        program = command.program();
        arguments = command.arguments();
        standardInput = command.standardInput();
        operation = command.operation();
        anchor = command.anchor();
        return std::make_unique<FakeChildProcess>(state);
    }
};

class M6PfAnchorQProcessRunnerTests : public QObject {
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

    static SessionSnapshot snapshot() {
        const auto value =
            SessionSnapshot::create(validConfig(), validFacts(), 11434, "runner-test");
        if (!value)
            qFatal("Could not create synthetic PF runner snapshot");
        return *value;
    }

    static QStringList expectedInstallArguments() {
        return {"-a", "llm_interceptor/runner-test", "-f", "-"};
    }

    static QStringList expectedRemoveArguments() {
        return {"-a", "llm_interceptor/runner-test", "-F", "rules"};
    }

  private slots:
    void installAndRemoveUseOnlyFixedProgramArgumentsAndInput() {
        const auto session = snapshot();
        for (const bool install : {true, false}) {
            FakeAuthorization authorization;
            FakeChildFactory factory;
            QProcessPfAnchorCommandRunner runner(factory);
            PfAnchorOperations operations(authorization, runner);

            const auto result = install ? operations.install(session, "lease-token")
                                        : operations.remove(session, "lease-token");

            QVERIFY(result.success);
            QVERIFY(result.mayHaveApplied);
            QCOMPARE(factory.createCalls, 1);
            QCOMPARE(factory.program, QString("/sbin/pfctl"));
            QCOMPARE(factory.anchor, QString("llm_interceptor/runner-test"));
            if (install) {
                QCOMPARE(factory.operation, PfAnchorOperation::Install);
                QCOMPARE(factory.arguments, expectedInstallArguments());
                QCOMPARE(factory.standardInput, session.pfRules().toUtf8());
            } else {
                QCOMPARE(factory.operation, PfAnchorOperation::RemoveRules);
                QCOMPARE(factory.arguments, expectedRemoveArguments());
                QVERIFY(factory.standardInput.isEmpty());
            }
            QCOMPARE(factory.state->input, factory.standardInput);
            QVERIFY(factory.state->writeClosed);
            QVERIFY(factory.state->finished);
            QVERIFY(factory.state->reaped);
            QVERIFY(!factory.state->killed);
            QVERIFY(!factory.state->running);
            QCOMPARE(factory.state->startTimeoutMs, PfAnchorOperations::commandTimeoutMs);
            QVERIFY(factory.state->finishTimeoutMs > 0);
        }
    }

    void failedSpawnDoesNotClaimProcessStartedOrApplied() {
        const auto session = snapshot();
        FakeAuthorization authorization;
        FakeChildFactory factory;
        factory.state->startSucceeds = false;
        QProcessPfAnchorCommandRunner runner(factory);
        PfAnchorOperations operations(authorization, runner);

        const auto result = operations.install(session, "lease-token");

        QVERIFY(!result.success);
        QVERIFY(!result.mayHaveApplied);
        QCOMPARE(result.statusCode, QString("command_failed"));
        QCOMPARE(factory.createCalls, 1);
        QVERIFY(!factory.state->processStarted);
        QVERIFY(!factory.state->running);
        QVERIFY(!factory.state->killed);
        QVERIFY(!factory.state->reaped);
    }

    void ambiguousStartFailureAfterLaunchKillsAndReapsTheProcess() {
        const auto session = snapshot();
        FakeAuthorization authorization;
        FakeChildFactory factory;
        factory.state->startSucceeds = false;
        factory.state->startedDespiteStartFailure = true;
        QProcessPfAnchorCommandRunner runner(factory);
        PfAnchorOperations operations(authorization, runner);

        const auto result = operations.install(session, "lease-token");

        QVERIFY(!result.success);
        QVERIFY(result.mayHaveApplied);
        QCOMPARE(result.statusCode, QString("command_failed"));
        QVERIFY(factory.state->processStarted);
        QVERIFY(factory.state->killed);
        QVERIFY(factory.state->finished);
        QVERIFY(factory.state->reaped);
        QVERIFY(!factory.state->running);
    }

    void partialStdinWriteFailureKillsAndReapsTheChild() {
        const auto session = snapshot();
        FakeAuthorization authorization;
        FakeChildFactory factory;
        factory.state->maximumWriteSize = 7;
        factory.state->failAfterPartialWrite = true;
        QProcessPfAnchorCommandRunner runner(factory);
        PfAnchorOperations operations(authorization, runner);

        const auto result = operations.install(session, "lease-token");

        QVERIFY(!result.success);
        QVERIFY(result.mayHaveApplied);
        QCOMPARE(result.statusCode, QString("command_failed"));
        QCOMPARE(factory.state->writeCalls, 2);
        QCOMPARE(factory.state->input.size(), qsizetype(7));
        QVERIFY(factory.state->killed);
        QVERIFY(factory.state->finished);
        QVERIFY(factory.state->reaped);
        QVERIFY(!factory.state->running);
    }

    void shortStdinWritesAreRetriedUntilAllRulesAreDelivered() {
        const auto session = snapshot();
        FakeAuthorization authorization;
        FakeChildFactory factory;
        factory.state->maximumWriteSize = 7;
        QProcessPfAnchorCommandRunner runner(factory);
        PfAnchorOperations operations(authorization, runner);

        const auto result = operations.install(session, "lease-token");

        QVERIFY(result.success);
        QCOMPARE(factory.state->writeCalls, (session.pfRules().toUtf8().size() + 6) / 7);
        QCOMPARE(factory.state->input, session.pfRules().toUtf8());
        QVERIFY(factory.state->writeClosed);
        QVERIFY(factory.state->reaped);
        QVERIFY(!factory.state->running);
    }

    void outputLimitKillsAndReapsWithoutExposingCapturedText() {
        const auto session = snapshot();
        FakeAuthorization authorization;
        FakeChildFactory factory;
        factory.state->stdoutBytes = QByteArray(40 * 1024, 'S');
        factory.state->stderrBytes = QByteArray(2 * PfAnchorOperations::maximumOutputBytes, 'E');
        QProcessPfAnchorCommandRunner runner(factory);
        PfAnchorOperations operations(authorization, runner);

        const auto result = operations.install(session, "lease-token");

        QVERIFY(!result.success);
        QVERIFY(result.mayHaveApplied);
        QCOMPARE(result.statusCode, QString("output_limit_exceeded"));
        QVERIFY(factory.state->killed);
        QVERIFY(factory.state->reaped);
        QVERIFY(!factory.state->running);
        QVERIFY(!result.statusCode.contains('S'));
        QVERIFY(!result.statusCode.contains('E'));
        QVERIFY(!factory.state->stdoutReadLimits.isEmpty());
        QVERIFY(!factory.state->stderrReadLimits.isEmpty());
        QCOMPARE(factory.state->stdoutReadLimits.size(), factory.state->stderrReadLimits.size());
        QCOMPARE(factory.state->stderrReadLimits.first(),
                 PfAnchorOperations::maximumOutputBytes - factory.state->stdoutBytesRead + 1);
        QCOMPARE(factory.state->stdoutBytesRead + factory.state->stderrBytesRead,
                 PfAnchorOperations::maximumOutputBytes + 1);
        QVERIFY(!factory.state->stderrBytes.isEmpty());
    }

    void timeoutKillsWaitsForExitAndReapsTheChild() {
        const auto session = snapshot();
        FakeAuthorization authorization;
        FakeChildFactory factory;
        factory.state->holdOpen = true;
        QProcessPfAnchorCommandRunner runner(factory);
        PfAnchorOperations operations(authorization, runner);

        const auto result = operations.install(session, "lease-token");

        QVERIFY(!result.success);
        QVERIFY(result.mayHaveApplied);
        QCOMPARE(result.statusCode, QString("timed_out"));
        QVERIFY(factory.state->readyReadWaitCalls > 0);
        QVERIFY(factory.state->killed);
        QVERIFY(factory.state->finished);
        QVERIFY(factory.state->reaped);
        QVERIFY(!factory.state->running);
    }

    void nonzeroExitPreservesExitCodeAndIsNotReportedAsSuccess() {
        const auto session = snapshot();
        FakeAuthorization authorization;
        FakeChildFactory factory;
        factory.state->code = 73;
        QProcessPfAnchorCommandRunner runner(factory);
        PfAnchorOperations operations(authorization, runner);

        const auto result = operations.install(session, "lease-token");

        QVERIFY(!result.success);
        QVERIFY(result.mayHaveApplied);
        QCOMPARE(result.statusCode, QString("nonzero_exit"));
        QVERIFY(factory.state->finished);
        QVERIFY(factory.state->reaped);
        QVERIFY(!factory.state->running);
    }
};

QTEST_GUILESS_MAIN(M6PfAnchorQProcessRunnerTests)
#include "M6PfAnchorQProcessRunnerTests.moc"
