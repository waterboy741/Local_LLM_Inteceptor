#include "HelperDispatcher.hpp"
namespace interceptor {
namespace {
bool sameSnapshot(const SessionSnapshot &first, const SessionSnapshot &second) {
    const auto &a = first.config();
    const auto &b = second.config();
    const auto &x = first.facts();
    const auto &y = second.facts();
    return a.interfaceName == b.interfaceName && a.clientIp == b.clientIp &&
           a.serverIp == b.serverIp && a.serverPort == b.serverPort && a.apiPaths == b.apiPaths &&
           a.explicitProxy == b.explicitProxy && first.proxyPort() == second.proxyPort() &&
           first.anchor() == second.anchor() && x.interfaceName == y.interfaceName &&
           x.researchIp == y.researchIp && x.researchMac == y.researchMac &&
           x.clientMac == y.clientMac && x.serverMac == y.serverMac &&
           x.prefixLength == y.prefixLength && x.proxyServerIp == y.proxyServerIp &&
           x.proxyServerPort == y.proxyServerPort && x.proxyListenPort == y.proxyListenPort &&
           x.interfaceUp == y.interfaceUp && x.sameLink == y.sameLink &&
           x.anchorAttached == y.anchorAttached && x.proxyReady == y.proxyReady &&
           x.authorized == y.authorized;
}
} // namespace
HelperDispatcher::HelperDispatcher(SystemOperations &operations, const SessionSnapshot &permitted,
                                   const VerifiedPeer &trusted, QByteArray capability,
                                   QObject *parent, MonotonicClock monotonicClock)
    : QObject(parent), permitted_(permitted), trusted_(trusted), capability_(std::move(capability)),
      session_(operations, this), monotonicClock_(std::move(monotonicClock)) {
    connect(&session_, &NetworkSession::stateChanged, this, &HelperDispatcher::stateChanged);
}
bool HelperDispatcher::ready() const {
    Q_ASSERT(QThread::currentThread() == thread());
    return !terminal_ && trusted_.transportAuthenticated && !trusted_.auditIdentity.isEmpty() &&
           trusted_.auditIdentity.size() <= 256 && capability_.size() >= 32 &&
           capability_.size() <= 128;
}
std::optional<qint64> HelperDispatcher::trustedMonotonicNowMs() const {
    Q_ASSERT(QThread::currentThread() == thread());
    if (!monotonicClock_)
        return std::nullopt;
    try {
        const auto nowMs = monotonicClock_();
        if (nowMs < 0)
            return std::nullopt;
        return nowMs;
    } catch (...) {
        return std::nullopt;
    }
}
bool HelperDispatcher::dispatch(const VerifiedPeer &peer, const HelperCommand &command) {
    Q_ASSERT(QThread::currentThread() == thread());
    if (!ready() || !peer.transportAuthenticated || peer.uid != trusted_.uid ||
        peer.auditIdentity != trusted_.auditIdentity || command.capability != capability_ ||
        command.anchor != permitted_.anchor() || command.nowMs < 0)
        return false;
    switch (command.type) {
    case HelperCommand::Type::Start:
        if (!command.snapshot || !sameSnapshot(*command.snapshot, permitted_) ||
            command.nowMs < lastTimeMs_)
            return false;
        if (!session_.start(permitted_, command.nowMs)) {
            revokeIfCleaned();
            return false;
        }
        lastTimeMs_ = command.nowMs;
        return true;
    case HelperCommand::Type::Heartbeat:
        if (command.snapshot || session_.state() != NetworkSession::State::Active ||
            command.nowMs < lastTimeMs_)
            return false;
        session_.heartbeat(command.nowMs);
        lastTimeMs_ = command.nowMs;
        return true;
    case HelperCommand::Type::Watchdog:
        if (command.snapshot || session_.state() != NetworkSession::State::Active ||
            command.nowMs < lastTimeMs_)
            return false;
        lastTimeMs_ = command.nowMs;
        {
            const bool result = session_.checkWatchdog(command.nowMs);
            revokeIfCleaned();
            return result;
        }
    case HelperCommand::Type::Stop:
        if (command.snapshot)
            return false;
        {
            const bool result = session_.stop();
            revokeIfCleaned();
            return result;
        }
    }
    return false;
}
bool HelperDispatcher::scheduledWatchdogTick() {
    Q_ASSERT(QThread::currentThread() == thread());
    if (terminal_ || session_.state() != NetworkSession::State::Active)
        return false;
    if (!monotonicClock_) {
        session_.checkWatchdog(-1);
        revokeIfCleaned();
        return false;
    }
    const auto clockValue = trustedMonotonicNowMs();
    if (!clockValue || *clockValue < lastTimeMs_) {
        session_.checkWatchdog(-1);
        revokeIfCleaned();
        return false;
    }
    const auto nowMs = *clockValue;
    lastTimeMs_ = nowMs;
    const auto result = session_.checkWatchdog(nowMs);
    revokeIfCleaned();
    return result;
}
void HelperDispatcher::revokeIfCleaned() {
    if (session_.state() == NetworkSession::State::Idle) {
        terminal_ = true;
        capability_.fill(char(0));
        capability_.clear();
    }
}
} // namespace interceptor
