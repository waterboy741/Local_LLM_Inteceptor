#pragma once
#include <QHostAddress>
#include <QPointer>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <memory>

// Deliberately small synthetic endpoint, not a reusable HTTP parser. The upstream
// emits Content-Length requests; chunked client decoding is the proxy's job.
class MockOllama : public QTcpServer {
  public:
    QList<QByteArray> bodies;
    QList<QByteArray> headers;
    bool streaming = false;
    bool stall = false;
    bool completed = false;
    bool truncateResponse = false;
    int disconnectedClients = 0;
    int responseStatus = 200;
    QByteArray responseHeaders;
    bool echoBody = false;

    MockOllama() {
        connect(this, &QTcpServer::newConnection, this, [this] {
            while (hasPendingConnections()) {
                auto *socket = nextPendingConnection();
                auto buffer = std::make_shared<QByteArray>();
                connect(socket, &QTcpSocket::disconnected, this, [this, socket] {
                    ++disconnectedClients;
                    socket->deleteLater();
                });
                connect(socket, &QTcpSocket::readyRead, this, [this, socket, buffer] {
                    buffer->append(socket->readAll());
                    const auto split = buffer->indexOf("\r\n\r\n");
                    if (split < 0)
                        return;
                    const auto head = buffer->left(split);
                    qint64 length = 0;
                    for (const auto &line : head.split('\n')) {
                        if (line.trimmed().toLower().startsWith("content-length:"))
                            length = line.mid(line.indexOf(':') + 1).trimmed().toLongLong();
                    }
                    if (buffer->size() < split + 4 + length)
                        return;
                    headers.append(head);
                    bodies.append(buffer->mid(split + 4, length));
                    buffer->remove(0, split + 4 + length);
                    if (stall)
                        return;
                    if (truncateResponse) {
                        socket->write("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort");
                        socket->disconnectFromHost();
                    } else if (streaming) {
                        const QByteArray first = "{\"response\":\"Hello\",\"done\":false}\n";
                        const QByteArray last = "{\"response\":\".\",\"done\":true}\n";
                        socket->write("HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\n"
                                      "Transfer-Encoding: chunked\r\n\r\n");
                        socket->write(QByteArray::number(first.size(), 16) + "\r\n" + first +
                                      "\r\n");
                        QPointer<QTcpSocket> guarded(socket);
                        QTimer::singleShot(300, this, [this, guarded, last] {
                            completed = true;
                            if (guarded) {
                                guarded->write(QByteArray::number(last.size(), 16) + "\r\n" + last +
                                               "\r\n0\r\n\r\n");
                            }
                        });
                    } else {
                        const bool noBody = head.startsWith("HEAD ") || responseStatus == 204 ||
                                            responseStatus == 304;
                        const auto responseBody =
                            echoBody ? bodies.back() : QByteArray("{\"done\":true}");
                        socket->write("HTTP/1.1 " + QByteArray::number(responseStatus) +
                                      " Synthetic\r\nContent-Type: application/json\r\n" +
                                      (responseStatus == 204
                                           ? QByteArray()
                                           : QByteArray("Content-Length: ") +
                                                 QByteArray::number(responseBody.size()) + "\r\n") +
                                      responseHeaders + "\r\n" +
                                      (noBody ? QByteArray() : responseBody));
                    }
                });
            }
        });
        if (!listen(QHostAddress::LocalHost, 0))
            qFatal("Cannot listen on synthetic loopback endpoint");
    }
};
