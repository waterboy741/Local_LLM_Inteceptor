#pragma once
#include "NetworkSession.hpp"
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
  public:
    HelperDispatcher(SystemOperations &, const SessionSnapshot &permitted,
                     const VerifiedPeer &trusted, QByteArray capability, QObject *parent = nullptr);
    bool dispatch(const VerifiedPeer &transportPeer, const HelperCommand &);
    bool ready() const;
    NetworkSession::State state() const { return session_.state(); }
    QStringList status() const { return session_.status(); }
    OwnershipJournal journal() const { return session_.journal(); }

  private:
    SessionSnapshot permitted_;
    VerifiedPeer trusted_;
    QByteArray capability_;
    NetworkSession session_;
    qint64 lastTimeMs_ = 0;
    bool terminal_ = false;
    void revokeIfCleaned();
};
} // namespace interceptor
