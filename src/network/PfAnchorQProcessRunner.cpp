#include "PfAnchorQProcessRunner.hpp"

#include <QElapsedTimer>
#include <QProcess>
#include <QRegularExpression>

namespace interceptor {
namespace {
constexpr qsizetype maximumRulesBytes = 32 * 1024;
constexpr int reapTimeoutMs = 1000;

bool validOwnedAnchor(const QString &anchor) {
    static const QRegularExpression pattern("^llm_interceptor/[A-Za-z0-9_-]{1,48}$");
    return pattern.match(anchor).hasMatch();
}

bool isValidTypedCommand(const PfAnchorCommand &command, int timeoutMs,
                         qsizetype outputLimitBytes) {
    if (command.program() != QStringLiteral("/sbin/pfctl") || !validOwnedAnchor(command.anchor()) ||
        timeoutMs != PfAnchorOperations::commandTimeoutMs ||
        outputLimitBytes != PfAnchorOperations::maximumOutputBytes)
        return false;

    switch (command.operation()) {
    case PfAnchorOperation::Install:
        return command.arguments() == QStringList{"-a", command.anchor(), "-f", "-"} &&
               !command.standardInput().isEmpty() &&
               command.standardInput().size() <= maximumRulesBytes &&
               !command.standardInput().contains('\0');
    case PfAnchorOperation::RemoveRules:
        return command.arguments() == QStringList{"-a", command.anchor(), "-F", "rules"} &&
               command.standardInput().isEmpty();
    }
    return false;
}

bool isPermissionDiagnostic(const QByteArray &diagnostic) {
    const auto lower = diagnostic.toLower();
    return lower.contains("permission denied") || lower.contains("operation not permitted") ||
           lower.contains("must be root") || lower.contains("requires root");
}

class QProcessChild final : public PfAnchorChildProcess {
  public:
    explicit QProcessChild(const PfAnchorCommand &command)
        : program_(command.program()), arguments_(command.arguments()) {
        process_.setProcessChannelMode(QProcess::SeparateChannels);
        QObject::connect(&process_, &QProcess::started, &process_, [this] { startedEver_ = true; });
    }

    bool start(int timeoutMs) override {
        process_.start(program_, arguments_, QIODevice::ReadWrite);
        return process_.waitForStarted(timeoutMs);
    }
    bool started() const override {
        return startedEver_ || process_.state() != QProcess::NotRunning;
    }
    qint64 write(const char *data, qint64 length) override { return process_.write(data, length); }
    qint64 bytesToWrite() const override { return process_.bytesToWrite(); }
    bool waitForBytesWritten(int timeoutMs) override {
        return process_.waitForBytesWritten(timeoutMs);
    }
    void closeWriteChannel() override { process_.closeWriteChannel(); }
    bool waitForReadyRead(int timeoutMs) override { return process_.waitForReadyRead(timeoutMs); }
    QByteArray readStandardOutput(qint64 maximumBytes) override {
        return process_.read(maximumBytes);
    }
    QByteArray readStandardError(qint64 maximumBytes) override {
        process_.setReadChannel(QProcess::StandardError);
        const auto bytes = process_.read(maximumBytes);
        process_.setReadChannel(QProcess::StandardOutput);
        return bytes;
    }
    bool isRunning() const override { return process_.state() != QProcess::NotRunning; }
    bool normalExit() const override { return process_.exitStatus() == QProcess::NormalExit; }
    int exitCode() const override { return process_.exitCode(); }
    bool failed() const override {
        return process_.error() != QProcess::UnknownError && process_.error() != QProcess::Timedout;
    }
    void kill() override { process_.kill(); }
    bool waitForFinished(int timeoutMs) override { return process_.waitForFinished(timeoutMs); }

  private:
    QString program_;
    QStringList arguments_;
    QProcess process_;
    bool startedEver_ = false;
};

class QProcessChildFactory final : public PfAnchorChildProcessFactory {
  public:
    std::unique_ptr<PfAnchorChildProcess> create(const PfAnchorCommand &command) override {
#if defined(Q_OS_MACOS)
        return std::make_unique<QProcessChild>(command);
#else
        Q_UNUSED(command);
        return {};
#endif
    }
};

int remainingMs(const QElapsedTimer &timer, int timeoutMs) {
    return qMax(0, timeoutMs - static_cast<int>(timer.elapsed()));
}

} // namespace

QProcessPfAnchorCommandRunner::QProcessPfAnchorCommandRunner()
    : ownedFactory_(std::make_unique<QProcessChildFactory>()), factory_(ownedFactory_.get()) {}

QProcessPfAnchorCommandRunner::QProcessPfAnchorCommandRunner(PfAnchorChildProcessFactory &factory)
    : factory_(&factory) {}

PfAnchorCommandResult QProcessPfAnchorCommandRunner::execute(const PfAnchorCommand &command,
                                                             int timeoutMs,
                                                             qsizetype outputLimitBytes) {
    if (!isValidTypedCommand(command, timeoutMs, outputLimitBytes))
        return {};
    auto child = factory_->create(command);
    if (!child)
        return {};

    QElapsedTimer elapsed;
    elapsed.start();
    PfAnchorCommandResult result;
    qsizetype collectedOutputBytes = 0;
    bool permissionDiagnostic = false;
    const auto collect = [&]() {
        const auto remaining = outputLimitBytes - collectedOutputBytes;
        const auto stdoutBytes = child->readStandardOutput(remaining + 1);
        if (stdoutBytes.size() > remaining)
            return PfAnchorCommandStatus::OutputLimitExceeded;
        const auto stderrBytes = child->readStandardError(remaining - stdoutBytes.size() + 1);
        const auto newBytes = stdoutBytes.size() + stderrBytes.size();
        if (newBytes > remaining)
            return PfAnchorCommandStatus::OutputLimitExceeded;
        collectedOutputBytes += newBytes;
        permissionDiagnostic = permissionDiagnostic || isPermissionDiagnostic(stderrBytes);
        return PfAnchorCommandStatus::Completed;
    };
    const auto terminate = [&](PfAnchorCommandStatus status) {
        child->kill();
        result.processReaped = child->waitForFinished(reapTimeoutMs) || !child->isRunning();
        result.status = result.processReaped ? status : PfAnchorCommandStatus::Failed;
        result.exitCode = child->exitCode();
        result.started = child->started() || result.started;
        return result;
    };

    const auto startRemaining = remainingMs(elapsed, timeoutMs);
    const auto startSucceeded = child->start(startRemaining);
    result.started = child->started();
    if (!startSucceeded) {
        if (result.started)
            return terminate(remainingMs(elapsed, timeoutMs) <= 0 ? PfAnchorCommandStatus::TimedOut
                                                                  : PfAnchorCommandStatus::Failed);
        result.status = PfAnchorCommandStatus::Failed;
        return result;
    }
    result.started = true;

    const auto &input = command.standardInput();
    qint64 written = 0;
    while (written < input.size()) {
        const auto remaining = remainingMs(elapsed, timeoutMs);
        if (remaining <= 0)
            return terminate(PfAnchorCommandStatus::TimedOut);
        const auto count = child->write(input.constData() + written, input.size() - written);
        if (count < 0)
            return terminate(PfAnchorCommandStatus::Failed);
        written += count;
        const auto collectStatus = collect();
        if (collectStatus != PfAnchorCommandStatus::Completed)
            return terminate(collectStatus);
        if (count == 0 || child->bytesToWrite() > 0) {
            if (!child->waitForBytesWritten(remainingMs(elapsed, timeoutMs)))
                return terminate(remainingMs(elapsed, timeoutMs) <= 0
                                     ? PfAnchorCommandStatus::TimedOut
                                     : PfAnchorCommandStatus::Failed);
        }
    }
    while (child->bytesToWrite() > 0) {
        const auto remaining = remainingMs(elapsed, timeoutMs);
        if (remaining <= 0)
            return terminate(PfAnchorCommandStatus::TimedOut);
        if (!child->waitForBytesWritten(remaining))
            return terminate(remainingMs(elapsed, timeoutMs) <= 0 ? PfAnchorCommandStatus::TimedOut
                                                                  : PfAnchorCommandStatus::Failed);
        const auto collectStatus = collect();
        if (collectStatus != PfAnchorCommandStatus::Completed)
            return terminate(collectStatus);
    }
    child->closeWriteChannel();

    while (child->isRunning()) {
        const auto remaining = remainingMs(elapsed, timeoutMs);
        if (remaining <= 0)
            return terminate(PfAnchorCommandStatus::TimedOut);
        child->waitForReadyRead(qMin(remaining, 50));
        const auto collectStatus = collect();
        if (collectStatus != PfAnchorCommandStatus::Completed)
            return terminate(collectStatus);
        if (child->failed() && child->isRunning())
            return terminate(PfAnchorCommandStatus::Failed);
    }
    const auto collectStatus = collect();
    if (collectStatus != PfAnchorCommandStatus::Completed)
        return terminate(collectStatus);
    result.processReaped = child->waitForFinished(reapTimeoutMs) || !child->isRunning();
    if (!result.processReaped) {
        result.status = PfAnchorCommandStatus::Failed;
        result.started = true;
        result.exitCode = child->exitCode();
        return result;
    }
    result.exitCode = child->exitCode();
    result.status = child->normalExit() && result.exitCode != 0 && permissionDiagnostic
                        ? PfAnchorCommandStatus::PermissionDenied
                        : (child->normalExit() ? PfAnchorCommandStatus::Completed
                                               : PfAnchorCommandStatus::Failed);
    return result;
}

} // namespace interceptor
