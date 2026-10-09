#include "ProxyServer.hpp"
#include <QAbstractHttpServer>
#include <QHash>
#include <QHttpServerConfiguration>
#include <QHttpServerRequest>
#include <QHttpServerResponder>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QMetaEnum>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QPointer>
#include <QTcpServer>
#include <QTcpSocket>
#include <QThread>
#include <QTimer>
#include <deque>
#include <mutex>
#include <set>
namespace interceptor {
namespace {
using Status = QHttpServerResponder::StatusCode;
std::set<QByteArray> excludedHeaders(const QHttpHeaders &headers) {
    std::set<QByteArray> excluded{"connection",
                                  "keep-alive",
                                  "proxy-authenticate",
                                  "proxy-authorization",
                                  "te",
                                  "trailer",
                                  "transfer-encoding",
                                  "upgrade",
                                  "content-length",
                                  "host"};
    for (const auto &pair : headers.toListOfPairs())
        if (pair.first.toLower() == "connection") {
            for (const auto &token : pair.second.split(','))
                excluded.insert(token.trimmed().toLower());
        }
    return excluded;
}
class LimitedTcpServer : public QTcpServer {
  public:
    using QTcpServer::QTcpServer;
    int count = 0;
    QHash<quint16, QPointer<QTcpSocket>> sockets;
    void incomingConnection(qintptr descriptor) override {
        auto *socket = new QTcpSocket(this);
        if (!socket->setSocketDescriptor(descriptor)) {
            delete socket;
            return;
        }
        if (count >= 24) {
            socket->abort();
            socket->deleteLater();
            return;
        }
        ++count;
        const auto remotePort = socket->peerPort();
        sockets.insert(remotePort, socket);
        // Deletion must wait until active responders release their stream/socket reference.
        connect(socket, &QTcpSocket::disconnected, this, [this, remotePort] {
            --count;
            sockets.remove(remotePort);
        });
        addPendingConnection(socket);
    }
};
struct Transfer {
    std::unique_ptr<QHttpServerResponder> responder;
    QNetworkReply *reply = nullptr;
    QPointer<QTcpSocket> downstream;
    bool started = false, completed = false, noBody = false;
};
class Engine : public QAbstractHttpServer {
  public:
    SessionConfig config;
    ProxyOptions options;
    QNetworkAccessManager manager{this};
    LimitedTcpServer listener{this};
    std::vector<std::shared_ptr<Transfer>> transfers;
    mutable std::mutex mutex;
    std::deque<ObservedRequest> observations;
    quint64 nextId = 1;
    std::size_t retainedBytes = 0;
    Engine(SessionConfig value, ProxyOptions limits)
        : config(std::move(value)), options(std::move(limits)) {
        QHttpServerConfiguration limitsConfig;
        limitsConfig.setMaximumBodySize(static_cast<qint64>(options.maxBodyBytes));
        limitsConfig.setMaximumUrlSize(4096);
        limitsConfig.setMaximumTotalHeaderSize(32768);
        limitsConfig.setMaximumHeaderFieldSize(8192);
        limitsConfig.setMaximumHeaderFieldCount(100);
        limitsConfig.setKeepAliveTimeout(std::chrono::seconds(2));
        setConfiguration(limitsConfig);
        listener.setMaxPendingConnections(24);
    }
    bool begin() {
        return listener.listen(QHostAddress::LocalHost, static_cast<quint16>(options.listenPort)) &&
               bind(&listener);
    }
    void shutdown() {
        listener.close();
        const auto active = transfers;
        for (auto &transfer : active)
            transfer->reply->abort();
    }
    void missingHandler(const QHttpServerRequest &, QHttpServerResponder &responder) override {
        responder.write(Status::BadRequest);
    }
    bool handleRequest(const QHttpServerRequest &incoming,
                       QHttpServerResponder &responder) override {
        const auto headers = incoming.headers();
        int lengths = 0;
        bool transferEncoding = false;
        for (const auto &pair : headers.toListOfPairs()) {
            if (pair.first.toLower() == "content-length")
                ++lengths;
            if (pair.first.toLower() == "transfer-encoding")
                transferEncoding = true;
        }
        if (lengths > 1 || (lengths && transferEncoding) || headers.contains("upgrade") ||
            incoming.method() == QHttpServerRequest::Method::Connect ||
            incoming.method() == QHttpServerRequest::Method::Unknown) {
            responder.write(Status::BadRequest);
            return true;
        }
        if (transfers.size() >= 8) {
            responder.write(Status::ServiceUnavailable);
            return true;
        }
        QUrl target = incoming.url();
        target.setScheme("http");
        target.setHost(config.serverIp);
        target.setPort(config.serverPort);
        target.setUserInfo({});
        target.setFragment({});
        QNetworkRequest request(target);
        request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                             QNetworkRequest::ManualRedirectPolicy);
        request.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);
        request.setTransferTimeout(options.timeoutMs);
        request.setAttribute(QNetworkRequest::CookieLoadControlAttribute, QNetworkRequest::Manual);
        request.setAttribute(QNetworkRequest::CookieSaveControlAttribute, QNetworkRequest::Manual);
        const auto excluded = excludedHeaders(headers);
        QHttpHeaders forwarded;
        for (const auto &pair : headers.toListOfPairs())
            if (!excluded.contains(pair.first.toLower()))
                forwarded.append(pair.first, pair.second);
        request.setHeaders(forwarded);
        // Explicit encoding header disables QNAM's automatic decompression.
        if (!request.hasRawHeader("Accept-Encoding"))
            request.setRawHeader("Accept-Encoding", "identity");
        const auto method = QByteArray(QMetaEnum::fromType<QHttpServerRequest::Method>().valueToKey(
                                           static_cast<int>(incoming.method())))
                                .toUpper();
        auto transfer = std::make_shared<Transfer>();
        transfer->responder = std::make_unique<QHttpServerResponder>(std::move(responder));
        transfer->downstream = listener.sockets.value(incoming.remotePort());
        transfer->reply = manager.sendCustomRequest(request, method, incoming.body());
        transfer->reply->setReadBufferSize(65536);
        transfers.push_back(transfer);
        const QString path = incoming.url().path();
        const QByteArray body = incoming.body();
        const bool matches =
            incoming.method() == QHttpServerRequest::Method::Post &&
            config.apiPaths.contains(path) &&
            incoming.value("Content-Type").split(';').first().trimmed().toLower() ==
                "application/json" &&
            !headers.contains("content-encoding");
        auto *timer = new QTimer(transfer->reply);
        timer->setInterval(50);
        connect(timer, &QTimer::timeout, this, [transfer] {
            if (!transfer->completed && transfer->responder &&
                transfer->responder->isResponseCanceled())
                transfer->reply->abort();
        });
        timer->start();
        const auto beginResponse = [this, transfer, matches, path, body, method] {
            if (transfer->started || transfer->completed)
                return;
            const int status =
                transfer->reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            if (!status)
                return;
            auto outgoing = transfer->reply->headers();
            const auto excluded = excludedHeaders(outgoing);
            QHttpHeaders filtered;
            for (const auto &pair : outgoing.toListOfPairs())
                if (!excluded.contains(pair.first.toLower()))
                    filtered.append(pair.first, pair.second);
            transfer->noBody = method == "HEAD" || status == 204 || status == 304;
            if (transfer->noBody)
                transfer->responder->write(filtered, static_cast<Status>(status));
            else
                transfer->responder->writeBeginChunked(filtered, static_cast<Status>(status));
            transfer->started = true;
            if (matches) {
                QJsonParseError error;
                const auto json = QJsonDocument::fromJson(body, &error);
                if (error.error == QJsonParseError::NoError && json.isObject()) {
                    const std::lock_guard lock(mutex);
                    if (body.size() > 8 * 1024 * 1024)
                        return;
                    while (
                        !observations.empty() &&
                        (observations.size() >= options.maxHistory ||
                         retainedBytes + static_cast<std::size_t>(body.size()) > 8 * 1024 * 1024)) {
                        retainedBytes -= static_cast<std::size_t>(observations.front().body.size());
                        observations.pop_front();
                    }
                    retainedBytes += static_cast<std::size_t>(body.size());
                    observations.push_back(
                        {nextId++, QString::fromLatin1(method), path, body, status});
                }
            }
        };
        connect(transfer->reply, &QNetworkReply::metaDataChanged, this, beginResponse);
        const auto cleanup = [this, transfer, timer] {
            if (transfer->completed)
                return;
            transfer->completed = true;
            timer->stop();
            transfer->responder.reset();
            if (transfer->downstream &&
                transfer->downstream->state() == QAbstractSocket::UnconnectedState)
                transfer->downstream->deleteLater();
            std::erase(transfers, transfer);
            transfer->reply->deleteLater();
        };
        const auto flush = [transfer, beginResponse, cleanup] {
            if (transfer->completed)
                return;
            beginResponse();
            if (!transfer->downstream || transfer->responder->isResponseCanceled()) {
                cleanup();
                transfer->reply->abort();
                return;
            }
            if (!transfer->started)
                return;
            if (transfer->downstream->bytesToWrite() > 65536)
                return;
            if (transfer->reply->bytesAvailable()) {
                const auto bytes = transfer->reply->read(16384);
                if (!transfer->noBody)
                    transfer->responder->writeChunk(bytes);
            }
            if (!transfer->reply->isFinished() || transfer->reply->bytesAvailable())
                return;
            const auto error = transfer->reply->error();
            const bool statusError =
                (error >= 201 && error <= 299) || (error >= 401 && error <= 499);
            if (error != QNetworkReply::NoError && !statusError)
                transfer->downstream->abort();
            else if (!transfer->noBody)
                transfer->responder->writeEndChunked({});
            cleanup();
        };
        connect(timer, &QTimer::timeout, this, flush);
        connect(transfer->reply, &QNetworkReply::readyRead, this, flush);
        connect(transfer->reply, &QNetworkReply::finished, this,
                [transfer, beginResponse, flush, cleanup] {
                    if (transfer->completed)
                        return;
                    beginResponse();
                    if (transfer->started) {
                        flush();
                        return;
                    }
                    transfer->responder->write(transfer->reply->error() ==
                                                       QNetworkReply::TimeoutError
                                                   ? Status::GatewayTimeout
                                                   : Status::BadGateway);
                    cleanup();
                });
        return true;
    }
};
} // namespace
struct ProxyServer::Impl {
    QThread thread;
    Engine *engine = nullptr;
    quint16 port = 0;
};
ProxyServer::ProxyServer(QObject *parent) : QObject(parent) {}
ProxyServer::~ProxyServer() { stop(); }
bool ProxyServer::start(const SessionConfig &config, const ProxyOptions &options) {
    Q_ASSERT(QThread::currentThread() == thread());
    if (impl_ || config.serverPort < 1 || config.serverPort > 65535 || config.apiPaths.isEmpty() ||
        options.listenAddress != "127.0.0.1" || options.listenPort < 0 ||
        options.listenPort > 65535 || options.timeoutMs < 1 || options.maxBodyBytes < 1 ||
        options.maxBodyBytes > 16 * 1024 * 1024 || options.maxHistory < 1 ||
        options.maxHistory > 1000)
        return false;
    QHostAddress address;
    if (!address.setAddress(config.serverIp) ||
        address.protocol() != QAbstractSocket::IPv4Protocol || address.isMulticast() ||
        address == QHostAddress::AnyIPv4 || address == QHostAddress::Broadcast)
        return false;
    impl_ = std::make_unique<Impl>();
    // Construct all network resources on the worker thread; GUI calls do not perform relay work.
    auto *anchor = new QObject;
    anchor->moveToThread(&impl_->thread);
    impl_->thread.start();
    QMetaObject::invokeMethod(
        anchor,
        [this, config, options, anchor] {
            impl_->engine = new Engine(config, options);
            if (impl_->engine->begin())
                impl_->port = impl_->engine->listener.serverPort();
            delete anchor;
        },
        Qt::BlockingQueuedConnection);
    if (!impl_->port) {
        stop();
        return false;
    }
    return true;
}
void ProxyServer::stop() {
    Q_ASSERT(QThread::currentThread() == thread());
    if (!impl_)
        return;
    QMetaObject::invokeMethod(
        impl_->engine,
        [this] {
            impl_->engine->shutdown();
            delete impl_->engine;
            impl_->engine = nullptr;
        },
        Qt::BlockingQueuedConnection);
    impl_->thread.quit();
    impl_->thread.wait();
    impl_.reset();
}
quint16 ProxyServer::listenPort() const { return impl_ ? impl_->port : 0; }
std::vector<ObservedRequest> ProxyServer::history() const {
    Q_ASSERT(QThread::currentThread() == thread());
    if (!impl_)
        return {};
    const std::lock_guard lock(impl_->engine->mutex);
    return {impl_->engine->observations.begin(), impl_->engine->observations.end()};
}
} // namespace interceptor
