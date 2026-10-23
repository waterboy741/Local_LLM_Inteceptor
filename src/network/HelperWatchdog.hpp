#pragma once

#include "HelperDispatcher.hpp"

#include <QPointer>
#include <QTimer>

#include <functional>
#include <memory>

namespace interceptor {

class HelperWatchdogTimer {
  public:
    virtual ~HelperWatchdogTimer() = default;
    virtual void setTimeoutHandler(std::function<void()> handler) = 0;
    virtual void start(int intervalMs) = 0;
    virtual void stop() = 0;
    virtual bool isActive() const = 0;
};

class HelperWatchdog final : public QObject {
    Q_OBJECT
  public:
    static constexpr int defaultIntervalMs = 250;
    static constexpr int maximumIntervalMs = 1000;

    explicit HelperWatchdog(HelperDispatcher &dispatcher, int intervalMs = defaultIntervalMs,
                            QObject *parent = nullptr);
    HelperWatchdog(HelperDispatcher &dispatcher, std::unique_ptr<HelperWatchdogTimer> timer,
                   int intervalMs = defaultIntervalMs, QObject *parent = nullptr);
    ~HelperWatchdog() override;

    bool isRunning() const;

  private:
    void initialize(HelperDispatcher &dispatcher, int intervalMs);
    void updateForState(NetworkSession::State state);
    void tick();

    QPointer<HelperDispatcher> dispatcher_;
    std::unique_ptr<HelperWatchdogTimer> timer_;
    int intervalMs_ = defaultIntervalMs;
    bool tickInProgress_ = false;
};

} // namespace interceptor
