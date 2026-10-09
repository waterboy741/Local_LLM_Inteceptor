#include "ProxyServer.hpp"
#include <QAbstractHttpServer>
#include <QElapsedTimer>
#include <QHash>
#include <QHttpServerConfiguration>
#include <QHttpServerRequest>
#include <QHttpServerResponder>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QMetaEnum>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QPointer>
#include <QSet>
#include <QTcpServer>
#include <QTcpSocket>
#include <QThread>
#include <QTimer>
#include <atomic>
#include <deque>
#include <mutex>
#include <set>
namespace interceptor {
namespace {
std::atomic<quint64> requestSequence{1};
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
bool boundedJson(const QJsonValue &value, int depth = 0) {
    if (depth > 32)
        return false;
    if (value.isObject())
        for (const auto &child : value.toObject())
            if (!boundedJson(child, depth + 1))
                return false;
    if (value.isArray())
        for (const auto &child : value.toArray())
            if (!boundedJson(child, depth + 1))
                return false;
    return true;
}
bool validEdit(const QByteArray &body, const QString &path, std::size_t maximum) {
    if (body.size() > static_cast<qsizetype>(maximum))
        return false;
    QJsonParseError error;
    const auto document = QJsonDocument::fromJson(body, &error);
    if (error.error != QJsonParseError::NoError || !document.isObject() ||
        !boundedJson(document.object()))
        return false;
    const auto object = document.object();
    if (!object.value("model").isString() || object.value("model").toString().isEmpty())
        return false;
    if (path == "/api/generate" && object.contains("prompt") && !object.value("prompt").isString())
        return false;
    if (path == "/api/chat" && object.contains("messages")) {
        if (!object.value("messages").isArray())
            return false;
        for (const auto &message : object.value("messages").toArray()) {
            if (!message.isObject())
                return false;
            const auto entry = message.toObject();
            const auto role = entry.value("role");
            if (!role.isString() ||
                !QStringList{"system", "user", "assistant", "tool"}.contains(role.toString()) ||
                !entry.value("content").isString())
                return false;
        }
    }
    return true;
}
bool replaceField(QJsonObject &object, const QStringList &path, int depth,
                  const QJsonValue &value) {
    const auto key = path[depth];
    if (!object.contains(key))
        return false;
    if (depth + 1 == path.size()) {
        if (object.value(key) == value)
            return false;
        object.insert(key, value);
        return true;
    }
    if (!object.value(key).isObject())
        return false;
    auto child = object.value(key).toObject();
    if (!replaceField(child, path, depth + 1, value))
        return false;
    object.insert(key, child);
    return true;
}
bool validModification(const ModificationOptions &options) {
    if (options.holdTimeoutMs < 1 || options.holdTimeoutMs > 300000 || options.maxHeld < 1 ||
        options.maxHeld > 8 || options.maxEditableBytes < 1 || options.maxEditableBytes > 1048576 ||
        options.maxHeld * options.maxEditableBytes > 8 * 1048576 || options.rules.size() > 32)
        return false;
    QSet<QString> ids;
    for (const auto &rule : options.rules) {
        if (rule.id.isEmpty() || rule.id.size() > 64 || ids.contains(rule.id) ||
            !rule.path.startsWith('/') || rule.path.size() > 4096 || rule.model.size() > 256 ||
            rule.fieldPath.isEmpty() || rule.fieldPath.size() > 16 || rule.value.isUndefined() ||
            !boundedJson(rule.value))
            return false;
        for (const auto &field : rule.fieldPath)
            if (field.isEmpty() || field.size() > 128)
                return false;
        if (QJsonDocument(QJsonArray{rule.value}).toJson(QJsonDocument::Compact).size() > 65536)
            return false;
        ids.insert(rule.id);
    }
    return true;
}
class LimitedTcpServer : public QTcpServer {
  public:
    using QTcpServer::QTcpServer;
    int count = 0;
    QHash<QTcpSocket *, int> responding;
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
        connect(socket, &QTcpSocket::disconnected, this, [this, remotePort, socket] {
            --count;
            if (sockets.value(remotePort) == socket)
                sockets.remove(remotePort);
            if (!responding.contains(socket))
                socket->deleteLater();
        });
        addPendingConnection(socket);
    }
};
struct Transfer {
    std::unique_ptr<QHttpServerResponder> responder;
    QNetworkReply *reply = nullptr;
    QPointer<QTcpSocket> downstream;
    QElapsedTimer stalled;
    quint16 remotePort = 0;
    bool started = false, completed = false, noBody = false;
};
struct Hold {
    QHttpServerRequest incoming;
    std::unique_ptr<QHttpServerResponder> responder;
    QPointer<QTcpSocket> socket;
    HeldRequest info;
    QElapsedTimer elapsed;
};
class Engine : public QAbstractHttpServer {
  public:
    bool shuttingDown = false;
    ModificationOptions modification;
    std::vector<std::shared_ptr<Hold>> holds;
    QTimer holdTimer{this};
    SessionConfig config;
    ProxyOptions options;
    QNetworkAccessManager manager{this};
    LimitedTcpServer listener{this};
    std::vector<std::shared_ptr<Transfer>> transfers;
    mutable std::mutex mutex;
    std::deque<ObservedRequest> observations;
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
        holdTimer.setInterval(25);
        connect(&holdTimer, &QTimer::timeout, this, [this] {
            const auto current = holds;
            for (const auto &hold : current) {
                if (!hold->socket || hold->responder->isResponseCanceled()) {
                    discardHold(hold);
                    continue;
                }
                if (hold->elapsed.elapsed() >= modification.holdTimeoutMs)
                    releaseHold(hold, hold->info.originalBody, {"deadline: original"});
            }
        });
        holdTimer.start();
    }
    bool begin() {
        return listener.listen(QHostAddress::LocalHost, static_cast<quint16>(options.listenPort)) &&
               bind(&listener);
    }
    void shutdown() {
        shuttingDown = true;
        listener.close();
        holdTimer.stop();
        const auto pending = holds;
        for (const auto &hold : pending)
            discardHold(hold);
        const auto active = transfers;
        for (auto &transfer : active) {
            transfer->completed = true;
            QObject::disconnect(transfer->reply, nullptr, this, nullptr);
            const auto timers = transfer->reply->findChildren<QTimer *>();
            for (auto *timer : timers)
                timer->stop();
            transfer->responder.reset();
            transfer->reply->abort();
        }
        transfers.clear();
    }
    void missingHandler(const QHttpServerRequest &, QHttpServerResponder &responder) override {
        responder.write(Status::BadRequest);
    }
    void discardHold(const std::shared_ptr<Hold> &hold) {
        hold->responder.reset();
        if (hold->socket) {
            if (--listener.responding[hold->socket.data()] == 0)
                listener.responding.remove(hold->socket.data());
            if (hold->socket->state() == QAbstractSocket::UnconnectedState &&
                !listener.responding.contains(hold->socket.data()))
                hold->socket->deleteLater();
        }
        std::erase(holds, hold);
    }
    void releaseHold(const std::shared_ptr<Hold> &hold, const QByteArray &body, QStringList audit) {
        // Move responder ownership into the relay before releasing the hold's socket reference.
        process(hold->incoming, *hold->responder, body, std::move(audit), true, hold->info.id);
        discardHold(hold);
    }
    bool handleRequest(const QHttpServerRequest &incoming,
                       QHttpServerResponder &responder) override {
        return process(incoming, responder, incoming.body(), {}, false, 0);
    }
    bool process(const QHttpServerRequest &incoming, QHttpServerResponder &responder,
                 QByteArray sendBody, QStringList audit, bool bypass, quint64 requestId) {
        if (shuttingDown) {
            responder.write(Status::ServiceUnavailable);
            return true;
        }
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
        if (transfers.size() + holds.size() >= 8 && !bypass) {
            responder.write(Status::ServiceUnavailable);
            return true;
        }
        const auto excluded = excludedHeaders(headers);
        QHttpHeaders forwarded;
        QHash<QByteArray, QByteArray> combined;
        QList<QByteArray> names;
        const std::set<QByteArray> listFields{"accept",
                                              "accept-charset",
                                              "accept-encoding",
                                              "accept-language",
                                              "cache-control",
                                              "pragma",
                                              "via",
                                              "warning",
                                              "if-match",
                                              "if-none-match",
                                              "prefer"};
        for (const auto &pair : headers.toListOfPairs()) {
            const auto name = pair.first.toLower();
            if (excluded.contains(name))
                continue;
            if (!combined.contains(name)) {
                combined.insert(name, pair.second);
                names.append(name);
                continue;
            }
            if (name == "cookie")
                combined[name] += "; " + pair.second;
            else if (listFields.contains(name))
                combined[name] += ", " + pair.second;
            else {
                responder.write(Status::BadRequest);
                return true;
            }
        }
        for (const auto &name : names)
            forwarded.append(name, combined.value(name));
        const QString incomingPath = incoming.url().path();
        const bool candidate =
            incoming.method() == QHttpServerRequest::Method::Post &&
            config.apiPaths.contains(incomingPath) &&
            incoming.value("Content-Type").split(';').first().trimmed().toLower() ==
                "application/json" &&
            !headers.contains("content-encoding");
        const auto auth = incoming.value("Authorization");
        const bool signedBody =
            headers.contains("digest") || headers.contains("content-md5") ||
            headers.contains("signature") || headers.contains("signature-input") ||
            (!auth.isEmpty() && !auth.startsWith("Bearer ") && !auth.startsWith("Basic "));
        if (!bypass && modification.mode == InterceptionMode::Modify && candidate && !signedBody &&
            validEdit(sendBody, incomingPath, modification.maxEditableBytes)) {
            auto object = QJsonDocument::fromJson(sendBody).object();
            bool changed = false;
            for (const auto &rule : modification.rules)
                if (rule.path == incomingPath &&
                    (rule.model.isEmpty() || object.value("model").toString() == rule.model)) {
                    if (replaceField(object, rule.fieldPath, 0, rule.value)) {
                        changed = true;
                        audit.append("rule: " + rule.id);
                    }
                }
            if (changed)
                sendBody = QJsonDocument(object).toJson(QJsonDocument::Compact);
            if (!validEdit(sendBody, incomingPath, modification.maxEditableBytes)) {
                sendBody = incoming.body();
                audit = {"rules invalid: original"};
            }
            if (modification.holdMatching) {
                if (holds.size() >= modification.maxHeld) {
                    responder.write(Status::ServiceUnavailable);
                    return true;
                }
                auto hold = std::make_shared<Hold>();
                hold->incoming = incoming;
                hold->socket = listener.sockets.value(incoming.remotePort());
                if (!hold->socket) {
                    responder.write(Status::ServiceUnavailable);
                    return true;
                }
                ++listener.responding[hold->socket.data()];
                hold->responder = std::make_unique<QHttpServerResponder>(std::move(responder));
                hold->info = {requestSequence.fetch_add(1), incomingPath, incoming.body(), sendBody,
                              modification.holdTimeoutMs,   audit};
                hold->elapsed.start();
                holds.push_back(hold);
                return true;
            }
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
        request.setHeaders(forwarded);
        // Explicit encoding header disables QNAM's automatic decompression.
        if (!request.hasRawHeader("Accept-Encoding"))
            request.setRawHeader("Accept-Encoding", "identity");
        const auto method = QByteArray(QMetaEnum::fromType<QHttpServerRequest::Method>().valueToKey(
                                           static_cast<int>(incoming.method())))
                                .toUpper();
        const auto downstream = listener.sockets.value(incoming.remotePort());
        if (!downstream) {
            responder.write(Status::ServiceUnavailable);
            return true;
        }
        auto transfer = std::make_shared<Transfer>();
        transfer->responder = std::make_unique<QHttpServerResponder>(std::move(responder));
        transfer->downstream = downstream;
        transfer->remotePort = incoming.remotePort();
        ++listener.responding[transfer->downstream.data()];
        transfer->reply = manager.sendCustomRequest(request, method, sendBody);
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
        const auto record = [this, matches, path, body, method, sendBody, audit,
                             requestId](int status) {
            if (matches) {
                QJsonParseError error;
                const auto json = QJsonDocument::fromJson(body, &error);
                if (error.error == QJsonParseError::NoError && json.isObject()) {
                    const std::lock_guard lock(mutex);
                    const auto recordBytes = static_cast<std::size_t>(
                        body.size() + (sendBody != body ? sendBody.size() : 0));
                    if (recordBytes > 8 * 1024 * 1024)
                        return;
                    while (!observations.empty() &&
                           (observations.size() >= options.maxHistory ||
                            retainedBytes + recordBytes > 8 * 1024 * 1024)) {
                        retainedBytes -=
                            static_cast<std::size_t>(observations.front().body.size() +
                                                     (observations.front().modified
                                                          ? observations.front().modifiedBody.size()
                                                          : 0));
                        observations.pop_front();
                    }
                    retainedBytes += recordBytes;
                    observations.push_back({requestId ? requestId : requestSequence.fetch_add(1),
                                            QString::fromLatin1(method), path, body, status, body,
                                            sendBody, audit, sendBody != body});
                }
            }
        };
        const auto beginResponse = [transfer, method, record] {
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
            record(status);
        };
        connect(transfer->reply, &QNetworkReply::metaDataChanged, this, beginResponse);
        const auto cleanup = [this, transfer, timer] {
            if (transfer->completed)
                return;
            transfer->completed = true;
            timer->stop();
            transfer->responder.reset();
            if (transfer->downstream && --listener.responding[transfer->downstream.data()] == 0)
                listener.responding.remove(transfer->downstream.data());
            if (transfer->downstream &&
                !listener.responding.contains(transfer->downstream.data()) &&
                transfer->downstream->state() == QAbstractSocket::UnconnectedState)
                transfer->downstream->deleteLater();
            std::erase(transfers, transfer);
            transfer->reply->deleteLater();
        };
        const auto flush = [this, transfer, beginResponse, cleanup] {
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
            if (transfer->downstream->bytesToWrite() > 65536) {
                if (!transfer->stalled.isValid())
                    transfer->stalled.start();
                if (transfer->stalled.elapsed() > options.timeoutMs) {
                    transfer->downstream->abort();
                    cleanup();
                    transfer->reply->abort();
                }
                return;
            }
            transfer->stalled.invalidate();
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
                [transfer, beginResponse, flush, cleanup, record] {
                    if (transfer->completed)
                        return;
                    beginResponse();
                    if (transfer->started) {
                        flush();
                        return;
                    }
                    const auto failure = transfer->reply->error() == QNetworkReply::TimeoutError
                                             ? Status::GatewayTimeout
                                             : Status::BadGateway;
                    record(static_cast<int>(failure));
                    transfer->responder->write(failure);
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
            impl_->engine->modification = modification_;
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
bool ProxyServer::setModificationOptions(const ModificationOptions &options) {
    Q_ASSERT(QThread::currentThread() == thread());
    if (!validModification(options))
        return false;
    if (impl_) {
        bool allowed = true;
        QMetaObject::invokeMethod(
            impl_->engine,
            [&] {
                if (!impl_->engine->holds.empty() && options.mode != InterceptionMode::Observe) {
                    allowed = false;
                    return;
                }
                impl_->engine->modification = options;
                if (options.mode == InterceptionMode::Observe) {
                    const auto pending = impl_->engine->holds;
                    for (const auto &hold : pending)
                        impl_->engine->releaseHold(hold, hold->info.originalBody,
                                                   {"mode Observe: original"});
                }
            },
            Qt::BlockingQueuedConnection);
        if (!allowed)
            return false;
    }
    modification_ = options;
    return true;
}
std::vector<HeldRequest> ProxyServer::held() const {
    Q_ASSERT(QThread::currentThread() == thread());
    std::vector<HeldRequest> result;
    if (!impl_)
        return result;
    QMetaObject::invokeMethod(
        impl_->engine,
        [&] {
            for (const auto &hold : impl_->engine->holds) {
                auto info = hold->info;
                info.remainingMs = std::max(0, impl_->engine->modification.holdTimeoutMs -
                                                   static_cast<int>(hold->elapsed.elapsed()));
                result.push_back(info);
            }
        },
        Qt::BlockingQueuedConnection);
    return result;
}
bool ProxyServer::resolveHeld(quint64 id, const QByteArray &editedBody, bool useOriginal) {
    Q_ASSERT(QThread::currentThread() == thread());
    if (!impl_)
        return false;
    bool result = false;
    QMetaObject::invokeMethod(
        impl_->engine,
        [&] {
            auto *engine = impl_->engine;
            const auto found = std::find_if(engine->holds.begin(), engine->holds.end(),
                                            [id](const auto &item) { return item->info.id == id; });
            if (found == engine->holds.end())
                return;
            const auto hold = *found;
            if (!hold->socket || hold->responder->isResponseCanceled()) {
                engine->discardHold(hold);
                return;
            }
            if (hold->elapsed.elapsed() >= engine->modification.holdTimeoutMs) {
                engine->releaseHold(hold, hold->info.originalBody, {"deadline: original"});
                return;
            }
            if (!useOriginal &&
                (engine->modification.mode != InterceptionMode::Modify ||
                 !validEdit(editedBody, hold->info.path, engine->modification.maxEditableBytes)))
                return;
            QStringList audit;
            if (!useOriginal)
                for (const auto &proposal : hold->info.audit)
                    audit.append("proposal " + proposal);
            audit.append(useOriginal ? "manual: original" : "manual: edited");
            engine->releaseHold(hold, useOriginal ? hold->info.originalBody : editedBody, audit);
            result = true;
        },
        Qt::BlockingQueuedConnection);
    return result;
}
} // namespace interceptor
