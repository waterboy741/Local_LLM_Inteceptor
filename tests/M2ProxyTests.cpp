#include "MockOllama.hpp"
#include "core/SessionConfig.hpp"
#include "proxy/ProxyServer.hpp"

#include <QElapsedTimer>
#include <QHostAddress>
#include <QPointer>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <QtTest>

#include <algorithm>
#include <memory>
#include <sys/resource.h>

using namespace interceptor;

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

    void localDeviceRoutesToSeparateLoopbackUpstream() {
        MockOllama mock;
        auto config = configFor(mock);
        config.interfaceName.clear();
        config.clientIp = "127.0.0.1";
        config.explicitProxy = true;
        QVERIFY(config.validate().isEmpty());
        ProxyServer proxy;
        QVERIFY(proxy.start(config));
        QVERIFY(proxy.listenPort() != mock.serverPort());
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        const QByteArray body = "{\"prompt\":\"local device\",\"stream\":false}";
        client.write(request(body));
        QTRY_COMPARE(mock.bodies.size(), 1);
        QCOMPARE(mock.bodies.front(), body);
        QTRY_VERIFY(client.peek(client.bytesAvailable()).contains("{\"done\":true}"));
        QTRY_COMPARE(proxy.history().size(), std::size_t(1));
        QCOMPARE(proxy.history().front().body, body);
    }

    void localListenerCannotForwardToItselfAndCanRestart_data() {
        QTest::addColumn<QString>("upstream");
        QTest::newRow("localhost") << QString("127.0.0.1");
        QTest::newRow("loopback-alias") << QString("127.0.0.2");
    }

    void localListenerCannotForwardToItselfAndCanRestart() {
        QFETCH(QString, upstream);
        QTcpServer portReservation;
        QVERIFY(portReservation.listen(QHostAddress::LocalHost, 0));
        const auto port = portReservation.serverPort();
        portReservation.close();
        SessionConfig config;
        config.clientIp = "127.0.0.1";
        config.serverIp = upstream;
        config.serverPort = port;
        config.explicitProxy = true;
        ProxyOptions options;
        options.listenPort = port;
        ProxyServer proxy;
        QVERIFY(!proxy.start(config, options));
        QCOMPARE(proxy.listenPort(), quint16(0));
        MockOllama mock;
        config.serverIp = "127.0.0.1";
        config.serverPort = mock.serverPort();
        QVERIFY(proxy.start(config, options));
        QCOMPARE(proxy.listenPort(), port);
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

    void completedConnectionChurnKeepsAdmissionAvailable() {
        MockOllama mock;
        ProxyServer proxy;
        ProxyOptions options;
        options.maxHistory = 5;
        QVERIFY(proxy.start(configFor(mock), options));
        for (int index = 0; index < 40; ++index) {
            QTcpSocket client;
            connectClient(client, proxy);
            QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
            client.write(request("{}"));
            QTRY_VERIFY(client.peek(client.bytesAvailable()).contains("{\"done\":true}"));
            client.disconnectFromHost();
            QTRY_COMPARE(client.state(), QAbstractSocket::UnconnectedState);
        }
        QCOMPARE(mock.bodies.size(), 40);
        QCOMPARE(proxy.history().size(), std::size_t(5));
        proxy.stop();
    }

    void pipelinedResponsesPreserveOrder() {
        MockOllama mock;
        mock.echoBody = true;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        QByteArray reply;
        connect(&client, &QTcpSocket::readyRead, this, [&] { reply += client.readAll(); });
        client.write(request("{\"order\":1}") + request("{\"order\":2}"));
        QTRY_COMPARE(mock.bodies.size(), 2);
        QTRY_VERIFY(reply.contains("{\"order\":2}"));
        QCOMPARE(reply.count("HTTP/1.1 200"), 2);
        QVERIFY(reply.indexOf("{\"order\":1}") < reply.indexOf("{\"order\":2}"));
    }

    void endToEndHeadersAndHopRemoval() {
        MockOllama mock;
        mock.responseHeaders = "Set-Cookie: synthetic-one=1\r\nSet-Cookie: synthetic-two=2\r\n";
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        auto wire = request("{}");
        wire.replace("Host:", "Accept: application/json\r\nAccept: text/plain\r\nCookie: "
                              "first=1\r\nCookie: second=2\r\nConnection: X-Private\r\nX-Private: "
                              "secret\r\nAuthorization: Bearer synthetic-token\r\nHost:");
        client.write(wire);
        QTRY_VERIFY(client.peek(client.bytesAvailable()).contains("{\"done\":true}"));
        const auto upstream = mock.headers.front();
        QVERIFY(!upstream.toLower().contains("\nx-private:"));
        QVERIFY(upstream.contains("Bearer synthetic-token"));
        QVERIFY(upstream.contains("first=1; second=2"));
        QList<QByteArray> values;
        for (const auto &line : upstream.split('\n')) {
            if (line.toLower().startsWith("accept:"))
                for (const auto &part : line.mid(line.indexOf(':') + 1).split(','))
                    values.append(part.trimmed());
        }
        QCOMPARE(values, QList<QByteArray>({"application/json", "text/plain"}));
        QCOMPARE(client.readAll().toLower().count("set-cookie:"), 2);
    }

    void unsupportedDuplicateHeadersAreRejectedBeforeForwarding() {
        MockOllama mock;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        for (const auto &duplicates :
             {QByteArray("X-Synthetic: one\r\nX-Synthetic: two\r\n"),
              QByteArray("Authorization: Bearer one\r\nAuthorization: Bearer two\r\n"),
              QByteArray("Content-Type: text/plain\r\n")}) {
            QTcpSocket client;
            connectClient(client, proxy);
            QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
            auto wire = request("{}");
            wire.replace("Host:", duplicates + "Host:");
            client.write(wire);
            QTRY_VERIFY(client.bytesAvailable() > 0);
            QVERIFY(client.readAll().startsWith("HTTP/1.1 400"));
        }
        QCOMPARE(mock.bodies.size(), 0);
        QVERIFY(proxy.history().empty());
    }

    void retainedBodiesRespectAggregateByteBudget() {
        MockOllama mock;
        ProxyServer proxy;
        ProxyOptions options;
        options.maxBodyBytes = 4 * 1024 * 1024;
        options.maxHistory = 100;
        QVERIFY(proxy.start(configFor(mock), options));
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        const QByteArray body = "{\"prompt\":\"" + QByteArray(3 * 1024 * 1024, 'x') + "\"}";
        quint64 firstId = 0;
        for (int index = 0; index < 3; ++index) {
            client.write(request(body));
            QTRY_COMPARE(mock.bodies.size(), index + 1);
            QTRY_VERIFY(client.peek(client.bytesAvailable()).contains("{\"done\":true}"));
            client.readAll();
            if (index == 0)
                firstId = proxy.history().front().id;
        }
        const auto history = proxy.history();
        QCOMPARE(history.size(), std::size_t(2));
        qsizetype retained = 0;
        for (const auto &item : history) {
            QCOMPARE(item.body, body);
            retained += item.body.size();
        }
        QVERIFY(retained <= 8 * 1024 * 1024);
        QVERIFY(history.front().id > firstId);
        QVERIFY(history.back().id > history.front().id);
    }

    void offlineBaseline() {
        if (!qEnvironmentVariableIsSet("INTERCEPTOR_RUN_BASELINE"))
            QSKIP("Opt-in measurement: set INTERCEPTOR_RUN_BASELINE=1 and run offlineBaseline.");
        constexpr int samples = 100;
        const QByteArray body = "{\"prompt\":\"" + QByteArray(1024, 'a') + "\",\"stream\":false}";
        const auto waitFor = [](QTcpSocket &socket, const QByteArray &needle) {
            QElapsedTimer deadline;
            deadline.start();
            while (!socket.peek(socket.bytesAvailable()).contains(needle) &&
                   deadline.elapsed() < 5000) {
                QCoreApplication::processEvents();
                QTest::qWait(1);
            }
            return socket.peek(socket.bytesAvailable()).contains(needle);
        };
        MockOllama mock;
        ProxyServer proxy;
        ProxyOptions options;
        options.maxHistory = 10;
        QVERIFY(proxy.start(configFor(mock), options));
        for (const bool proxied : {false, true}) {
            QTcpSocket client;
            client.connectToHost(QHostAddress::LocalHost,
                                 proxied ? proxy.listenPort() : mock.serverPort());
            QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
            std::vector<double> milliseconds;
            QElapsedTimer total;
            total.start();
            for (int sample = 0; sample < samples; ++sample) {
                QElapsedTimer timer;
                timer.start();
                client.write(request(body));
                QVERIFY(waitFor(client, "{\"done\":true}"));
                milliseconds.push_back(timer.nsecsElapsed() / 1000000.0);
                client.readAll();
            }
            const double seconds = total.nsecsElapsed() / 1000000000.0;
            std::sort(milliseconds.begin(), milliseconds.end());
            qInfo().noquote() << QString("BASELINE %1 samples=%2 body_bytes=%3 median_ms=%4 "
                                         "p95_ms=%5 requests_per_s=%6 request_body_bytes_per_s=%7")
                                     .arg(proxied ? "proxy" : "direct")
                                     .arg(samples)
                                     .arg(body.size())
                                     .arg(milliseconds[samples / 2], 0, 'f', 3)
                                     .arg(milliseconds[94], 0, 'f', 3)
                                     .arg(samples / seconds, 0, 'f', 1)
                                     .arg(samples * body.size() / seconds, 0, 'f', 1);
        }
        QCOMPARE(proxy.history().size(), std::size_t(10));
        for (const bool proxied : {false, true}) {
            MockOllama stream;
            stream.streaming = true;
            ProxyServer streamProxy;
            QVERIFY(streamProxy.start(configFor(stream)));
            QTcpSocket client;
            client.connectToHost(QHostAddress::LocalHost,
                                 proxied ? streamProxy.listenPort() : stream.serverPort());
            QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
            QElapsedTimer timer;
            timer.start();
            client.write(request("{\"stream\":true}"));
            QVERIFY(waitFor(client, "Hello"));
            const double firstByte = timer.nsecsElapsed() / 1000000.0;
            QVERIFY(!stream.completed);
            QVERIFY(waitFor(client, "\"done\":true"));
            qInfo().noquote()
                << QString(
                       "BASELINE %1 ndjson_first_payload_ms=%2 completion_ms=%3 mock_gap_ms=300")
                       .arg(proxied ? "proxy" : "direct")
                       .arg(firstByte, 0, 'f', 3)
                       .arg(timer.nsecsElapsed() / 1000000.0, 0, 'f', 3);
        }
        rusage usage{};
        QVERIFY(getrusage(RUSAGE_SELF, &usage) == 0);
#ifdef Q_OS_MACOS
        qInfo() << "BASELINE combined_test_process_peak_rss_bytes=" << usage.ru_maxrss;
#else
        qInfo() << "BASELINE combined_test_process_peak_rss_kib=" << usage.ru_maxrss;
#endif
        qInfo() << "BASELINE concurrency=1 polling_ms=1 history_rows=10 default_body_limit=1048576";
    }
};

QTEST_GUILESS_MAIN(M2ProxyTests)
#include "M2ProxyTests.moc"
