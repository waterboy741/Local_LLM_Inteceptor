#pragma once
#include "NetworkSession.hpp"
#include <functional>
namespace interceptor {
// Supplied by the trusted transport, never deserialized from a command body.
struct VerifiedPeer {
    quint32 uid = 0;
    QByteArray auditIdentity;
    bool transportAuthenticated = false;
};
struct HelperCommand {
    enum class Type { Start, Heartbeat, Watchdog, Stop };
    Type type = Type::Stop;
    QByteArray capability;
    QString anchor;
    std::optional<SessionSnapshot> snapshot;
    qint64 nowMs = 0;
};
class HelperDispatcher : public QObject {
    Q_OBJECT
  public:
    using MonotonicClock = std::function<qint64()>;
    HelperDispatcher(SystemOperations &, const SessionSnapshot &permitted,
                     const VerifiedPeer &trusted, QByteArray capability, QObject *parent = nullptr,
                     MonotonicClock monotonicClock = {});
    ~HelperDispatcher() override;
    bool dispatch(const VerifiedPeer &transportPeer, const HelperCommand &);
    bool ready() const;
    std::optional<qint64> trustedMonotonicNowMs() const;
    NetworkSession::State state() const { return session_.state(); }
    QStringList status() const { return session_.status(); }
    OwnershipJournal journal() const { return session_.journal(); }

  signals:
    void stateChanged(interceptor::NetworkSession::State);

  private:
    friend class HelperWatchdog;
    SessionSnapshot permitted_;
    VerifiedPeer trusted_;
    QByteArray capability_;
    NetworkSession session_;
    qint64 lastTimeMs_ = 0;
    bool terminal_ = false;
    MonotonicClock monotonicClock_;
    bool scheduledWatchdogTick();
    void revokeIfCleaned();
    void revokeCapability() noexcept;
};
} // namespace interceptor
