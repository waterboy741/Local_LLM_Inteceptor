#pragma once

#include "PfAnchorOperations.hpp"

#include <memory>

namespace interceptor {

// The factory and child are configured only from a typed PF anchor command;
// they do not expose an arbitrary executable/argument launch surface.
class PfAnchorChildProcess {
  public:
    virtual ~PfAnchorChildProcess() = default;
    virtual bool start(int timeoutMs) = 0;
    // True once start has succeeded or may still be in progress, even if the
    // process has already exited by the time the caller checks.
    virtual bool started() const = 0;
    virtual qint64 write(const char *data, qint64 length) = 0;
    virtual qint64 bytesToWrite() const = 0;
    virtual bool waitForBytesWritten(int timeoutMs) = 0;
    virtual void closeWriteChannel() = 0;
    virtual bool waitForReadyRead(int timeoutMs) = 0;
    virtual QByteArray readStandardOutput(qint64 maximumBytes) = 0;
    virtual QByteArray readStandardError(qint64 maximumBytes) = 0;
    virtual bool isRunning() const = 0;
    virtual bool normalExit() const = 0;
    virtual int exitCode() const = 0;
    virtual bool failed() const = 0;
    virtual void kill() = 0;
    virtual bool waitForFinished(int timeoutMs) = 0;
};

class PfAnchorChildProcessFactory {
  public:
    virtual ~PfAnchorChildProcessFactory() = default;
    virtual std::unique_ptr<PfAnchorChildProcess> create(const PfAnchorCommand &command) = 0;
};

class QProcessPfAnchorCommandRunner final : public PfAnchorCommandRunner {
  public:
    QProcessPfAnchorCommandRunner();
    explicit QProcessPfAnchorCommandRunner(PfAnchorChildProcessFactory &factory);

    PfAnchorCommandResult execute(const PfAnchorCommand &command, int timeoutMs,
                                  qsizetype outputLimitBytes) override;

  private:
    std::unique_ptr<PfAnchorChildProcessFactory> ownedFactory_;
    PfAnchorChildProcessFactory *factory_ = nullptr;
};

} // namespace interceptor
