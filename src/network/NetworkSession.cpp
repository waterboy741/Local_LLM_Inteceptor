#include "NetworkSession.hpp"
#include "ArpCodec.hpp"
#include <QDebug>
#include <QHostAddress>
#include <QRegularExpression>
#include <QScopedValueRollback>
#include <QThread>
namespace interceptor {
namespace {
bool usableMac(const QString &text) {
    static const QRegularExpression pattern("^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$");
    if (!pattern.match(text).hasMatch())
        return false;
    const auto bytes = QByteArray::fromHex(text.toLatin1());
    return bytes.size() == 6 && (static_cast<unsigned char>(bytes[0]) & 1) == 0 &&
           bytes != QByteArray(6, char(0));
}
bool usableIp(const QString &text, quint32 &value) {
    QHostAddress address;
    if (!address.setAddress(text) || address.protocol() != QAbstractSocket::IPv4Protocol ||
        address.isLoopback() || address.isMulticast())
        return false;
    value = address.toIPv4Address();
    const auto first = value >> 24;
    return first > 0 && first < 224 && address.toString() == text;
}
} // namespace
std::optional<SessionSnapshot> SessionSnapshot::create(const SessionConfig &config,
                                                       const NetworkFacts &facts, int proxyPort,
                                                       const QString &sessionId, QString *error) {
    const auto fail = [error](const QString &text) -> std::optional<SessionSnapshot> {
        if (error)
            *error = text;
        return std::nullopt;
    };
    if (error)
        error->clear();
    if (config.explicitProxy || !config.validate().isEmpty())
        return fail("ARP session requires valid distinct LAN client/server IPv4 and configuration");
    static const QRegularExpression interfacePattern("^[A-Za-z][A-Za-z0-9_.:-]{0,63}$"),
        idPattern("^[A-Za-z0-9_-]{1,48}$");
    if (!interfacePattern.match(config.interfaceName).hasMatch() ||
        facts.interfaceName != config.interfaceName)
        return fail("Interface evidence does not match the selected interface");
    if (!idPattern.match(sessionId).hasMatch() || proxyPort < 1 || proxyPort > 65535)
        return fail("Invalid session ID/proxy port");
    if (!facts.authorized || !facts.interfaceUp || !facts.sameLink || !facts.proxyReady ||
        !facts.anchorAttached)
        return fail("Preflight requires authorization, interface/link/proxy readiness and verified "
                    "dedicated anchor attachment");
    if (facts.proxyServerIp != config.serverIp || facts.proxyServerPort != config.serverPort ||
        facts.proxyListenPort != proxyPort)
        return fail("Proxy readiness endpoint does not match the immutable session route/listener");
    if (facts.prefixLength < 1 || facts.prefixLength > 30)
        return fail("Unsupported subnet prefix; initial lab requires /1 through /30");
    quint32 research = 0, client = 0, server = 0;
    if (!usableIp(facts.researchIp, research) || !usableIp(config.clientIp, client) ||
        !usableIp(config.serverIp, server) || research == client || research == server)
        return fail("Research/client/server must be usable distinct LAN IPv4 addresses");
    const quint32 mask = 0xffffffffU << (32 - facts.prefixLength), network = research & mask,
                  broadcast = network | ~mask;
    for (const auto ip : {research, client, server})
        if ((ip & mask) != network || ip == network || ip == broadcast)
            return fail("Peers must be usable hosts on the same selected subnet");
    if (!usableMac(facts.researchMac) || !usableMac(facts.clientMac) ||
        !usableMac(facts.serverMac) ||
        facts.researchMac.compare(facts.clientMac, Qt::CaseInsensitive) == 0 ||
        facts.researchMac.compare(facts.serverMac, Qt::CaseInsensitive) == 0 ||
        facts.clientMac.compare(facts.serverMac, Qt::CaseInsensitive) == 0)
        return fail("Peers require distinct nonzero unicast MAC addresses");
    SessionSnapshot snapshot;
    snapshot.config_ = config;
    snapshot.facts_ = facts;
    snapshot.proxyPort_ = proxyPort;
    snapshot.sessionId_ = sessionId;
    return snapshot;
}
QString SessionSnapshot::pfRules() const {
    const auto iface = '"' + config_.interfaceName + '"';
    const auto label = '"' + QString("llm_") + sessionId_ + '"';
    return QString("rdr on %1 inet proto tcp from %2 to %3 port %4 -> 127.0.0.1 port %5\n"
                   "pass in quick on %1 inet proto tcp from %2 to 127.0.0.1 port %5 flags S/SA "
                   "keep state label %6\n"
                   "pass in quick on %1 inet from %2 to %3 keep state label %6\n"
                   "pass in quick on %1 inet from %3 to %2 keep state label %6\n"
                   "pass out quick on %1 inet proto tcp from %7 to %3 port %4 flags S/SA keep "
                   "state label %6\n")
        .arg(iface, config_.clientIp, config_.serverIp, QString::number(config_.serverPort),
             QString::number(proxyPort_), label, facts_.researchIp);
}
QList<QByteArray> SessionSnapshot::redirectionFrames() const {
    const auto mac = [](const QString &value) { return QByteArray::fromHex(value.toLatin1()); };
    const auto research = mac(facts_.researchMac), client = mac(facts_.clientMac),
               server = mac(facts_.serverMac);
    return {ArpCodec::encode(
                {research, client, research, client, config_.serverIp, config_.clientIp, 2}),
            ArpCodec::encode(
                {research, server, research, server, config_.clientIp, config_.serverIp, 2})};
}
QList<QByteArray> SessionSnapshot::restorationFrames() const {
    const auto mac = [](const QString &value) { return QByteArray::fromHex(value.toLatin1()); };
    const auto research = mac(facts_.researchMac), client = mac(facts_.clientMac),
               server = mac(facts_.serverMac);
    return {
        ArpCodec::encode({research, client, server, client, config_.serverIp, config_.clientIp, 2}),
        ArpCodec::encode(
            {research, server, client, server, config_.clientIp, config_.serverIp, 2})};
}
bool OwnershipJournal::empty() const {
    return !previousForwarding && !previousSendRedirects && !pfToken && !sessionLease && !anchor &&
           !state && !arp && !neighbors;
}
NetworkSession::NetworkSession(SystemOperations &operations, QObject *parent)
    : QObject(parent), operations_(operations) {}
NetworkSession::~NetworkSession() {
    Q_ASSERT(QThread::currentThread() == thread());
    destroying_ = true;
    if (!journal_.empty() && !cleanup()) {
        if (snapshot_ && operations_.retainRecovery(*snapshot_, journal_))
            qWarning("Offline helper destroyed with cleanup pending; recovery journal transferred "
                     "to backend");
        else
            qWarning(
                "Offline helper destroyed with cleanup pending; recovery journal retention failed");
    }
}
void NetworkSession::setState(State value) {
    state_ = value;
    if (!destroying_)
        emit stateChanged(value);
}
bool NetworkSession::fail(const QString &text) {
    status_.append(text);
    cleanup();
    return false;
}
bool NetworkSession::start(const SessionSnapshot &snapshot, qint64 nowMs) {
    Q_ASSERT(QThread::currentThread() == thread());
    if (transitioning_ || state_ != State::Idle || !journal_.empty() || nowMs < 0)
        return false;
    const QScopedValueRollback<bool> guard(transitioning_, true);
    status_.clear();
    snapshot_ = snapshot;
    heartbeatMs_ = nowMs;
    setState(State::Starting);
    journal_.sessionLease = operations_.acquireSessionLease(snapshot);
    if (!journal_.sessionLease || journal_.sessionLease->isEmpty()) {
        journal_.sessionLease.reset();
        return fail("Exclusive session lease/fresh preflight unavailable");
    }
    if (!operations_.interfaceAvailable(snapshot))
        return fail("Preflight interface unavailable (mock evidence)");
    const auto forwarding = operations_.readSetting(NetworkSetting::Forwarding),
               redirects = operations_.readSetting(NetworkSetting::SendRedirects);
    if (!forwarding || !redirects)
        return fail("Cannot snapshot forwarding/redirect settings");
    journal_.pfToken = operations_.acquirePfReference();
    if (!journal_.pfToken || journal_.pfToken->isEmpty()) {
        journal_.pfToken.reset();
        return fail("PF enable reference unavailable");
    }
    journal_.anchor = true;
    journal_.state = true;
    if (!operations_.installAnchor(snapshot))
        return fail("Session anchor installation failed; cleanup uncertain owned effects");
    if (*forwarding != 1) {
        const auto changed =
            operations_.compareAndSetSetting(NetworkSetting::Forwarding, *forwarding, 1);
        if (changed == SettingChange::Applied)
            journal_.previousForwarding = *forwarding;
        else if (changed != SettingChange::Unchanged)
            return fail("Forwarding setup failed or concurrent change");
    }
    if (*redirects != 0) {
        const auto changed =
            operations_.compareAndSetSetting(NetworkSetting::SendRedirects, *redirects, 0);
        if (changed == SettingChange::Applied)
            journal_.previousSendRedirects = *redirects;
        else if (changed != SettingChange::Unchanged)
            return fail("Redirect suppression failed or concurrent change");
    }
    journal_.neighbors = true;
    journal_.arp = true;
    if (!operations_.beginArp(snapshot))
        return fail("ARP activation failed; restore attempted pair state");
    status_.append("Active simulated session; live routing unvalidated");
    setState(State::Active);
    return true;
}
void NetworkSession::heartbeat(qint64 nowMs) {
    Q_ASSERT(QThread::currentThread() == thread());
    if (state_ == State::Active && nowMs >= heartbeatMs_)
        heartbeatMs_ = nowMs;
}
bool NetworkSession::checkWatchdog(qint64 nowMs) {
    Q_ASSERT(QThread::currentThread() == thread());
    if (state_ != State::Active)
        return false;
    if (nowMs < heartbeatMs_ || nowMs - heartbeatMs_ >= watchdogTimeoutMs) {
        status_.append("Watchdog expired or monotonic clock regressed");
        stop();
        return false;
    }
    if (!operations_.interfaceAvailable(*snapshot_)) {
        interfaceLost();
        return false;
    }
    return true;
}
bool NetworkSession::interfaceLost() {
    Q_ASSERT(QThread::currentThread() == thread());
    status_.append("Selected interface lost");
    return stop();
}
bool NetworkSession::stop() {
    Q_ASSERT(QThread::currentThread() == thread());
    if (transitioning_)
        return false;
    const QScopedValueRollback<bool> guard(transitioning_, true);
    return cleanup();
}
bool NetworkSession::cleanup() {
    if (journal_.empty()) {
        snapshot_.reset();
        if (state_ != State::Idle)
            setState(State::Idle);
        return true;
    }
    setState(State::Cleaning);
    const auto pending = [this](const QString &message) {
        status_.append(message);
        setState(State::CleanupPending);
        return false;
    };
    const auto &snapshot = *snapshot_;
    if (journal_.arp) {
        if (!operations_.endArp(snapshot))
            return pending("ARP refresh stop failed; ownership retained");
        journal_.arp = false;
    }
    if (journal_.neighbors) {
        if (!operations_.restoreNeighbors(snapshot))
            return pending("Neighbor restoration failed; forwarding retained");
        journal_.neighbors = false;
    }
    if (journal_.anchor) {
        if (!operations_.removeAnchor(snapshot))
            return pending("Owned anchor cleanup failed");
        journal_.anchor = false;
    }
    if (journal_.state) {
        if (!operations_.clearOwnedState(snapshot))
            return pending("Owned state cleanup failed");
        journal_.state = false;
    }
    const auto restore = [this](NetworkSetting setting, std::optional<int> &previous, int applied) {
        if (!previous)
            return true;
        const auto current = operations_.readSetting(setting);
        if (!current) {
            status_.append("Cannot read setting during restoration");
            return false;
        }
        if (*current == *previous) {
            previous.reset();
            return true;
        }
        if (*current != applied) {
            status_.append("Concurrent setting change; restoration deferred");
            return false;
        }
        const auto restored = operations_.compareAndSetSetting(setting, applied, *previous);
        if (restored != SettingChange::Applied && restored != SettingChange::Unchanged) {
            status_.append(restored == SettingChange::Conflict
                               ? "Concurrent setting change; atomic restoration deferred"
                               : "Conditional setting restore failed");
            return false;
        }
        previous.reset();
        return true;
    };
    const bool redirectsRestored =
                   restore(NetworkSetting::SendRedirects, journal_.previousSendRedirects, 0),
               forwardingRestored =
                   restore(NetworkSetting::Forwarding, journal_.previousForwarding, 1);
    if (!redirectsRestored || !forwardingRestored)
        return pending("Settings ownership remains pending");
    if (journal_.pfToken) {
        if (!operations_.releasePfReference(*journal_.pfToken))
            return pending("Owned PF reference release failed");
        journal_.pfToken.reset();
    }
    if (journal_.sessionLease) {
        if (!operations_.releaseSessionLease(*journal_.sessionLease))
            return pending("Exclusive session lease release failed");
        journal_.sessionLease.reset();
    }
    status_.append("Owned simulated resources cleaned");
    snapshot_.reset();
    setState(State::Idle);
    return true;
}
} // namespace interceptor
