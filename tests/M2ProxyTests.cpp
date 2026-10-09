#include "core/SessionConfig.hpp"
#include "proxy/ProxyServer.hpp"

#include <QHostAddress>
#include <QPointer>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <QtTest>

#include <memory>

using namespace interceptor;

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
                        socket->write("HTTP/1.1 " + QByteArray::number(responseStatus) +
                                      " Synthetic\r\nContent-Type: application/json\r\n" +
                                      (responseStatus == 204
                                           ? QByteArray()
                                           : QByteArray("Content-Length: 13\r\n")) +
                                      responseHeaders + "\r\n" +
                                      (noBody ? QByteArray() : QByteArray("{\"done\":true}")));
                    }
                });
            }
        });
        if (!listen(QHostAddress::LocalHost, 0))
            qFatal("Cannot listen on synthetic loopback endpoint");
    }
};

class M2ProxyTests : public QObject {
    Q_OBJECT

  private:
    static SessionConfig configFor(const MockOllama &mock) {
        return {"synthetic0",
                "192.0.2.10",
                "127.0.0.1",
                int(mock.serverPort()),
                {"/api/generate", "/api/chat"}};
    }
    static QByteArray request(const QByteArray &body, const QByteArray &path = "/api/generate",
                              const QByteArray &type = "application/json") {
        return "POST " + path + " HTTP/1.1\r\nHost: untrusted.example:9\r\nContent-Type: " + type +
               "\r\nContent-Length: " + QByteArray::number(body.size()) + "\r\n\r\n" + body;
    }
    static void connectClient(QTcpSocket &client, ProxyServer &proxy) {
        client.connectToHost(QHostAddress::LocalHost, proxy.listenPort());
    }

  private slots:
    void exactBodyAndConfiguredDestination() {
        MockOllama mock;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        const QByteArray body =
            " { \"model\": \"synthetic\", \"prompt\": \"hello\", \"stream\": false } ";
        client.write(request(body));
        QTRY_COMPARE(mock.bodies.size(), 1);
        QCOMPARE(mock.bodies.front(), body);
        QTRY_VERIFY(client.peek(client.bytesAvailable()).contains("{\"done\":true}"));
        const auto response = client.readAll();
        QVERIFY(response.contains("200 OK"));
        QVERIFY(response.contains("{\"done\":true}"));
        QTRY_COMPARE(proxy.history().size(), std::size_t(1));
        QCOMPARE(proxy.history().front().body, body);
        QCOMPARE(proxy.history().front().path, QString("/api/generate"));
        proxy.stop();
    }

    void matchingAndBoundedRetention() {
        MockOllama mock;
        ProxyServer proxy;
        ProxyOptions options;
        options.maxHistory = 2;
        QVERIFY(proxy.start(configFor(mock), options));
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        for (int index = 0; index < 5; ++index) {
            client.write(request("{\"prompt\":\"" + QByteArray::number(index) + "\"}"));
            QTRY_COMPARE(mock.bodies.size(), index + 1);
            QTRY_VERIFY(client.peek(client.bytesAvailable()).contains("{\"done\":true}"));
            client.readAll();
        }
        QTRY_COMPARE(proxy.history().size(), std::size_t(2));
        QVERIFY(proxy.history().back().body.contains("4"));
        client.write(request("private nonmatching body", "/other"));
        QTRY_COMPARE(mock.bodies.size(), 6);
        QTRY_VERIFY(client.peek(client.bytesAvailable()).contains("{\"done\":true}"));
        client.readAll();
        client.write(request("private non-JSON body", "/api/generate", "text/plain"));
        QTRY_COMPARE(mock.bodies.size(), 7);
        QTRY_VERIFY(client.peek(client.bytesAvailable()).contains("{\"done\":true}"));
        client.readAll();
        QCOMPARE(proxy.history().size(), std::size_t(2));
        QVERIFY(proxy.history().back().body.contains("4"));
    }

    void incrementalNdjson() {
        MockOllama mock;
        mock.streaming = true;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        client.write(request("{\"stream\":true}"));
        QByteArray response;
        connect(&client, &QTcpSocket::readyRead, this, [&] { response += client.readAll(); });
        QTRY_VERIFY(response.contains("Hello"));
        QVERIFY2(!mock.completed, "Proxy buffered partial NDJSON until completion");
        QTRY_VERIFY(response.contains("\"done\":true"));
        QVERIFY(mock.completed);
    }

    void fragmentedAndChunkedRequest() {
        MockOllama mock;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        client.write("POST /api/generate HTTP/1.1\r\nHost: example\r\nContent-Type: "
                     "application/json\r\nTran");
        client.flush();
        QTest::qWait(20);
        QCOMPARE(mock.bodies.size(), 0);
        client.write("sfer-Encoding: chunked\r\n\r\n5\r\n{\"x\":\r\n2\r\n1}\r\n0\r\n\r\n");
        QTRY_COMPARE(mock.bodies.size(), 1);
        QCOMPARE(mock.bodies.front(), QByteArray("{\"x\":1}"));
    }

    void ambiguousFramingIsRejected() {
        MockOllama mock;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        for (const auto &framing :
             {QByteArray("Content-Length: 2\r\nTransfer-Encoding: chunked\r\n"),
              QByteArray("Content-Length: 2\r\nContent-Length: 3\r\n")}) {
            QTcpSocket client;
            connectClient(client, proxy);
            QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
            client.write("POST /api/generate HTTP/1.1\r\nHost: example\r\n" + framing +
                         "\r\n{}0\r\n\r\n");
            QTRY_VERIFY(client.bytesAvailable() > 0 ||
                        client.state() == QAbstractSocket::UnconnectedState);
            const auto reply = client.readAll();
            QVERIFY(!reply.startsWith("HTTP/1.1 200"));
        }
        QCOMPARE(mock.bodies.size(), 0);
    }

    void concurrentClientsAndShutdown() {
        MockOllama mock;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        QTcpSocket first, second;
        connectClient(first, proxy);
        connectClient(second, proxy);
        QTRY_COMPARE(first.state(), QAbstractSocket::ConnectedState);
        QTRY_COMPARE(second.state(), QAbstractSocket::ConnectedState);
        first.write(request("{\"client\":1}"));
        second.write(request("{\"client\":2}"));
        QTRY_COMPARE(mock.bodies.size(), 2);
        QTRY_VERIFY(first.bytesAvailable() > 0 && second.bytesAvailable() > 0);
        QCOMPARE(proxy.history().size(), std::size_t(2));
        proxy.stop();
        QTRY_COMPARE(first.state(), QAbstractSocket::UnconnectedState);
        QTRY_COMPARE(second.state(), QAbstractSocket::UnconnectedState);
    }

    void upstreamTimeout() {
        MockOllama mock;
        mock.stall = true;
        ProxyOptions options;
        options.timeoutMs = 150;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock), options));
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        client.write(request("{}"));
        QTRY_VERIFY(client.bytesAvailable() > 0);
        const auto reply = client.readAll();
        QVERIFY(reply.startsWith("HTTP/1.1 502") || reply.startsWith("HTTP/1.1 504"));
    }

    void truncatedRequestAndBodyLimit() {
        MockOllama mock;
        ProxyOptions options;
        options.maxBodyBytes = 32;
        options.timeoutMs = 150;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock), options));
        {
            QTcpSocket partial;
            connectClient(partial, proxy);
            QTRY_COMPARE(partial.state(), QAbstractSocket::ConnectedState);
            partial.write(
                "POST /api/generate HTTP/1.1\r\nHost: example\r\nContent-Length: 20\r\n\r\n{}");
            partial.flush();
            QTest::qWait(20);
            partial.abort();
        }
        QTcpSocket oversized;
        connectClient(oversized, proxy);
        QTRY_COMPARE(oversized.state(), QAbstractSocket::ConnectedState);
        oversized.write(request(QByteArray(100, 'x')));
        QTRY_VERIFY(oversized.bytesAvailable() > 0 ||
                    oversized.state() == QAbstractSocket::UnconnectedState);
        QVERIFY(!oversized.readAll().startsWith("HTTP/1.1 200"));
        QCOMPARE(mock.bodies.size(), 0);
        QVERIFY(proxy.history().empty());
    }

    void clientCancellationAndActiveStop() {
        MockOllama mock;
        mock.stall = true;
        ProxyOptions options;
        options.timeoutMs = 200;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock), options));
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        client.write(request("{}"));
        QTRY_COMPARE(mock.bodies.size(), 1);
        client.abort();
        QTRY_VERIFY(mock.disconnectedClients > 0);
        QTcpSocket pending;
        connectClient(pending, proxy);
        QTRY_COMPARE(pending.state(), QAbstractSocket::ConnectedState);
        pending.write(request("{}"));
        QTRY_COMPARE(mock.bodies.size(), 2);
        proxy.stop();
        QTRY_COMPARE(pending.state(), QAbstractSocket::UnconnectedState);
        QCOMPARE(proxy.listenPort(), quint16(0));
    }

    void refusedUpstreamAndMalformedMethod() {
        MockOllama mock;
        const auto config = configFor(mock);
        mock.close();
        ProxyServer proxy;
        QVERIFY(proxy.start(config));
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        client.write(request("{}"));
        QTRY_VERIFY(client.bytesAvailable() > 0);
        QVERIFY(client.readAll().startsWith("HTTP/1.1 502"));
        QTcpSocket malformed;
        connectClient(malformed, proxy);
        QTRY_COMPARE(malformed.state(), QAbstractSocket::ConnectedState);
        malformed.write("INVALID METHOD HTTP/1.1\r\nHost: example\r\n\r\n");
        QTRY_VERIFY(malformed.bytesAvailable() > 0 ||
                    malformed.state() == QAbstractSocket::UnconnectedState);
        QVERIFY(!malformed.readAll().startsWith("HTTP/1.1 200"));
    }

    void truncatedUpstreamDoesNotBecomeCompletedSuccess() {
        MockOllama mock;
        mock.truncateResponse = true;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        QByteArray reply;
        connect(&client, &QTcpSocket::readyRead, this, [&] { reply += client.readAll(); });
        client.write(request("{}"));
        QTRY_COMPARE(mock.bodies.size(), 1);
        QTRY_VERIFY(reply.contains("502") || client.state() == QAbstractSocket::UnconnectedState);
        if (reply.startsWith("HTTP/1.1 200"))
            QVERIFY2(!reply.endsWith("0\r\n\r\n"),
                     "Truncated upstream body became completed chunked success");
    }

    void occupiedPortFailureIsSafeAndRestartable() {
        MockOllama mock;
        ProxyServer proxy;
        ProxyOptions options;
        options.listenPort = mock.serverPort();
        QVERIFY(!proxy.start(configFor(mock), options));
        QCOMPARE(proxy.listenPort(), quint16(0));
        proxy.stop();
        proxy.stop();
        QVERIFY(proxy.start(configFor(mock)));
        QVERIFY(proxy.listenPort() != 0);
        proxy.stop();
    }

    void upstreamHttpErrorsRemainCompleteResponses() {
        for (const int status : {404, 500}) {
            MockOllama mock;
            mock.responseStatus = status;
            ProxyServer proxy;
            QVERIFY(proxy.start(configFor(mock)));
            QTcpSocket client;
            connectClient(client, proxy);
            QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
            client.write(request("{}"));
            QTRY_VERIFY(client.peek(client.bytesAvailable()).contains("0\r\n\r\n"));
            const auto reply = client.readAll();
            QVERIFY(reply.startsWith("HTTP/1.1 " + QByteArray::number(status)));
            QVERIFY(reply.contains("{\"done\":true}"));
        }
    }

    void repeatedStreamingCancellationReleasesCapacity() {
        MockOllama mock;
        mock.streaming = true;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        for (int index = 0; index < 10; ++index) {
            QTcpSocket client;
            connectClient(client, proxy);
            QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
            client.write(request("{}"));
            QTRY_VERIFY(client.peek(client.bytesAvailable()).contains("Hello"));
            client.abort();
            QTRY_VERIFY(mock.disconnectedClients >= index + 1);
        }
        QCOMPARE(mock.bodies.size(), 10);
    }

    void noBodyResponseSemantics() {
        for (const int status : {200, 204, 304}) {
            MockOllama mock;
            mock.responseStatus = status;
            ProxyServer proxy;
            QVERIFY(proxy.start(configFor(mock)));
            QTcpSocket client;
            connectClient(client, proxy);
            QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
            client.write(status == 200 ? QByteArray("HEAD /other HTTP/1.1\r\nHost: example\r\n\r\n")
                                       : request("{}"));
            QTRY_VERIFY(client.peek(client.bytesAvailable()).contains("\r\n\r\n"));
            const auto reply = client.readAll();
            QVERIFY(reply.startsWith("HTTP/1.1 " + QByteArray::number(status)));
            const auto split = reply.indexOf("\r\n\r\n");
            QVERIFY2(reply.mid(split + 4).isEmpty(), "HEAD/204/304 response contains body framing");
            if (status == 204)
                QVERIFY(!reply.left(split).toLower().contains("transfer-encoding:"));
        }
    }

    void cookieStateDoesNotLeakBetweenClients() {
        MockOllama mock;
        mock.responseHeaders = "Set-Cookie: synthetic-server=secret; Path=/\r\n";
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        {
            QTcpSocket first;
            connectClient(first, proxy);
            QTRY_COMPARE(first.state(), QAbstractSocket::ConnectedState);
            auto wire = request("{}");
            wire.replace("Host:", "Cookie: synthetic-client=value\r\nHost:");
            first.write(wire);
            QTRY_VERIFY(first.peek(first.bytesAvailable()).contains("{\"done\":true}"));
            QVERIFY(mock.headers.front().toLower().contains("cookie: synthetic-client=value"));
        }
        QTcpSocket second;
        connectClient(second, proxy);
        QTRY_COMPARE(second.state(), QAbstractSocket::ConnectedState);
        second.write(request("{}"));
        QTRY_COMPARE(mock.headers.size(), 2);
        QVERIFY(!mock.headers.back().toLower().contains("\ncookie:"));
    }
};

QTEST_GUILESS_MAIN(M2ProxyTests)
#include "M2ProxyTests.moc"
