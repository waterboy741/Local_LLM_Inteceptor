#include "SessionController.hpp"
#include <QThread>
namespace interceptor {
SessionController::SessionController(QObject *parent) : QObject(parent) {}
void SessionController::setState(State state) {
    state_ = state;
    emit stateChanged(state_);
}
bool SessionController::prepare(const SessionConfig &config) {
    Q_ASSERT(QThread::currentThread() == thread());
    if (state_ != State::Idle || !config.validate().isEmpty())
        return false;
    config_ = config;
    setState(State::Ready);
    return true;
}
void SessionController::stop() {
    Q_ASSERT(QThread::currentThread() == thread());
    if (state_ == State::Idle || state_ == State::Stopping)
        return;
    setState(State::Stopping);
    config_.reset();
    setState(State::Idle);
}
} // namespace interceptor
