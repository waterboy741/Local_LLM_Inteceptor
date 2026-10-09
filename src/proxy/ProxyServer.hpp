#pragma once
#include "core/SessionConfig.hpp"
#include <QByteArray>
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
};
struct ObservedRequest {
    quint64 id;
    QString method, path;
    QByteArray body;
    int status;
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

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace interceptor
