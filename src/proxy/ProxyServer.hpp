#pragma once
#include "core/SessionConfig.hpp"
#include <QByteArray>
#include <QJsonValue>
#include <QObject>
#include <memory>
#include <vector>
namespace interceptor {
struct ProxyOptions {
    QString listenAddress = "127.0.0.1";
    int listenPort = 0;
    int timeoutMs = 2000;
    std::size_t maxBodyBytes = 1048576;
    std::size_t maxHistory = 100;
    std::size_t maxHistoryBytes = 8 * 1024 * 1024;
};
enum class InterceptionMode { Observe, Modify };
enum class AutomaticOperation { None, ReplaceLastMessage, AppendToLastContent, ReplaceMessages };
struct JsonRule {
    QString id, path, model;
    QStringList fieldPath;
    QJsonValue value;
};
struct ModificationOptions {
    InterceptionMode mode = InterceptionMode::Observe;
    AutomaticOperation automaticOperation = AutomaticOperation::None;
    QJsonValue automaticMessage;
    QString automaticAppendText;
    bool holdMatching = false;
    int holdTimeoutMs = 30000;
    std::size_t maxHeld = 8, maxEditableBytes = 1048576;
    std::vector<JsonRule> rules;
};
struct HeldRequest {
    quint64 id;
    QString path;
    QByteArray originalBody, proposedBody;
    int remainingMs;
    QStringList audit;
};
struct ObservedRequest {
    quint64 id;
    QString method, path;
    QByteArray body;
    int status;
    QByteArray originalBody, modifiedBody;
    QStringList audit;
    bool modified = false;
};
class ProxyServer : public QObject {
    Q_OBJECT
  public:
    explicit ProxyServer(QObject *parent = nullptr);
    ~ProxyServer() override;
    bool start(const SessionConfig &, const ProxyOptions & = {});
    void stop();
    quint16 listenPort() const;
    std::vector<ObservedRequest> history() const;
    bool setModificationOptions(const ModificationOptions &);
    std::vector<HeldRequest> held() const;
    bool resolveHeld(quint64 id, const QByteArray &editedBody, bool useOriginal = false);
    bool loadOfflineReplay(const std::vector<ObservedRequest> &records);
    void clearOfflineReplay();

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    ModificationOptions modification_;
    std::vector<ObservedRequest> replayHistory_;
};
} // namespace interceptor
