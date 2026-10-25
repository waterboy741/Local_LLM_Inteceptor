#pragma once
#include "core/SessionConfig.hpp"
#include <QObject>
#include <QThread>
#include <optional>
namespace interceptor {
struct NetworkFacts {
    QString interfaceName, researchIp, researchMac, clientMac, serverMac, proxyServerIp;
    int proxyServerPort = 0, proxyListenPort = 0;
    int prefixLength = 24;
    bool interfaceUp = false, sameLink = false, anchorAttached = false, proxyReady = false,
         authorized = false;
};
class SessionSnapshot {
  public:
    static std::optional<SessionSnapshot> create(const SessionConfig &, const NetworkFacts &,
                                                 int proxyPort, const QString &sessionId,
                                                 QString *error = nullptr);
    const SessionConfig &config() const { return config_; }
    const NetworkFacts &facts() const { return facts_; }
    int proxyPort() const { return proxyPort_; }
    const QString &sessionId() const { return sessionId_; }
    QString anchor() const { return "llm_interceptor/" + sessionId_; }
    QString pfRules() const;
    QList<QByteArray> redirectionFrames() const;
    QList<QByteArray> restorationFrames() const;

  private:
    SessionSnapshot() = default;
    SessionConfig config_;
    NetworkFacts facts_;
    int proxyPort_ = 0;
    QString sessionId_;
};
enum class NetworkSetting { Forwarding, SendRedirects };
enum class SettingChange { Applied, Unchanged, Conflict, Failed };
struct OwnershipJournal;
class SystemOperations {
  public:
    virtual ~SystemOperations() = default;
    virtual std::optional<int> readSetting(NetworkSetting) = 0;
    virtual SettingChange compareAndSetSetting(NetworkSetting, int expected, int desired) = 0;
    virtual std::optional<QString> acquireSessionLease(const SessionSnapshot &) = 0;
    virtual bool releaseSessionLease(const QString &) = 0;
    virtual std::optional<QString> acquirePfReference() = 0;
    virtual bool releasePfReference(const QString &token) = 0;
    virtual bool installAnchor(const SessionSnapshot &) = 0;
    virtual bool removeAnchor(const SessionSnapshot &) = 0;
    virtual bool clearOwnedState(const SessionSnapshot &) = 0;
    virtual bool beginArp(const SessionSnapshot &) = 0;
    virtual bool endArp(const SessionSnapshot &) = 0;
    virtual bool restoreNeighbors(const SessionSnapshot &) = 0;
    virtual bool interfaceAvailable(const SessionSnapshot &) = 0;
    virtual bool retainRecovery(const SessionSnapshot &, const OwnershipJournal &) = 0;
};
struct OwnershipJournal {
    std::optional<int> previousForwarding, previousSendRedirects;
    std::optional<QString> pfToken, sessionLease;
    bool anchor = false, state = false, arp = false, neighbors = false;
    bool empty() const;
};
class NetworkSession : public QObject {
    Q_OBJECT
  public:
    enum class State { Idle, Starting, Active, Cleaning, CleanupPending };
    Q_ENUM(State)
    explicit NetworkSession(SystemOperations &, QObject *parent = nullptr);
    ~NetworkSession() override;
    bool start(const SessionSnapshot &, qint64 nowMs = 0);
    void heartbeat(qint64 nowMs);
    bool checkWatchdog(qint64 nowMs);
    bool interfaceLost();
    bool stop();
    State state() const {
        Q_ASSERT(QThread::currentThread() == thread());
        return state_;
    }
    QStringList status() const {
        Q_ASSERT(QThread::currentThread() == thread());
        return status_;
    }
    OwnershipJournal journal() const {
        Q_ASSERT(QThread::currentThread() == thread());
        return journal_;
    }
    std::optional<SessionSnapshot> snapshot() const {
        Q_ASSERT(QThread::currentThread() == thread());
        return snapshot_;
    }
    static constexpr qint64 watchdogTimeoutMs = 5000;
  signals:
    void stateChanged(interceptor::NetworkSession::State);

  private:
    void setState(State);
    bool cleanup();
    bool fail(const QString &);
    SystemOperations &operations_;
    State state_ = State::Idle;
    OwnershipJournal journal_;
    QStringList status_;
    std::optional<SessionSnapshot> snapshot_;
    qint64 heartbeatMs_ = 0;
    bool transitioning_ = false, destroying_ = false;
};
} // namespace interceptor
