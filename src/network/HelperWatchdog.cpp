#include "HelperWatchdog.hpp"

#include <QScopedValueRollback>
#include <QThread>

namespace interceptor {
namespace {
class QtHelperWatchdogTimer final : public QObject, public HelperWatchdogTimer {
  public:
    explicit QtHelperWatchdogTimer(QObject *parent = nullptr) : QObject(parent) {
        QObject::connect(&timer_, &QTimer::timeout, this, [this] {
            if (timeoutHandler_)
                timeoutHandler_();
        });
    }

    void setTimeoutHandler(std::function<void()> handler) override {
        timeoutHandler_ = std::move(handler);
    }
    void start(int intervalMs) override { timer_.start(intervalMs); }
    void stop() override { timer_.stop(); }
    bool isActive() const override { return timer_.isActive(); }

  private:
    QTimer timer_;
    std::function<void()> timeoutHandler_;
};
} // namespace

HelperWatchdog::HelperWatchdog(HelperDispatcher &dispatcher, int intervalMs, QObject *parent)
    : QObject(parent), timer_(std::make_unique<QtHelperWatchdogTimer>()) {
    initialize(dispatcher, intervalMs);
}

HelperWatchdog::HelperWatchdog(HelperDispatcher &dispatcher,
                               std::unique_ptr<HelperWatchdogTimer> timer, int intervalMs,
                               QObject *parent)
    : QObject(parent), timer_(std::move(timer)) {
    initialize(dispatcher, intervalMs);
}

HelperWatchdog::~HelperWatchdog() {
    if (timer_) {
        timer_->stop();
        timer_->setTimeoutHandler({});
    }
}

void HelperWatchdog::initialize(HelperDispatcher &dispatcher, int intervalMs) {
    Q_ASSERT(QThread::currentThread() == dispatcher.thread());
    if (!timer_)
        timer_ = std::make_unique<QtHelperWatchdogTimer>();
    dispatcher_ = &dispatcher;
    if (intervalMs > 0 && intervalMs <= maximumIntervalMs)
        intervalMs_ = intervalMs;
    timer_->setTimeoutHandler([this] { tick(); });
    connect(&dispatcher, &HelperDispatcher::stateChanged, this,
            [this](NetworkSession::State state) { updateForState(state); });
    connect(&dispatcher, &QObject::destroyed, this, [this] {
        dispatcher_.clear();
        if (timer_)
            timer_->stop();
    });
    updateForState(dispatcher.state());
}

bool HelperWatchdog::isRunning() const { return dispatcher_ && timer_ && timer_->isActive(); }

void HelperWatchdog::updateForState(NetworkSession::State state) {
    Q_ASSERT(QThread::currentThread() == thread());
    if (!dispatcher_ || !timer_ || state != NetworkSession::State::Active) {
        if (timer_)
            timer_->stop();
        return;
    }
    if (!timer_->isActive())
        timer_->start(intervalMs_);
}

void HelperWatchdog::tick() {
    Q_ASSERT(QThread::currentThread() == thread());
    if (tickInProgress_ || !dispatcher_ || !timer_ || !timer_->isActive() ||
        dispatcher_->state() != NetworkSession::State::Active)
        return;
    const QScopedValueRollback<bool> guard(tickInProgress_, true);
    dispatcher_->scheduledWatchdogTick();
}

} // namespace interceptor
