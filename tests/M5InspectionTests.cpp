#include "MockOllama.hpp"
#include "gui/MainWindow.hpp"
#include "inspection/InspectionArchive.hpp"
#include "proxy/ProxyServer.hpp"
#include "session/SessionController.hpp"

#include <QBuffer>
#include <QCheckBox>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QSpinBox>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <QtTest>

using namespace interceptor;

class M5InspectionTests : public QObject {
    Q_OBJECT

  private:
    static bool loopbackAvailable() {
        QTcpServer probe;
        return probe.listen(QHostAddress::LocalHost, 0);
    }
    static ObservedRequest record(quint64 id, bool modified = false) {
        ObservedRequest item;
        item.id = id;
        item.method = "POST";
        item.path = "/api/generate";
        item.body = R"({"model":"synthetic","prompt":"hello","options":{"seed":7}})";
        item.status = 200;
        item.originalBody = item.body;
        item.modifiedBody = modified ? R"({"model":"synthetic","prompt":"changed"})" : QByteArray();
        item.audit = modified ? QStringList{"synthetic-rule"} : QStringList{};
        item.modified = modified;
        return item;
    }
    static SessionConfig configFor(const MockOllama &mock) {
        return {"synthetic0", "192.0.2.10", "127.0.0.1", int(mock.serverPort()), {"/api/generate"}};
    }

  private slots:
    void exportImportRoundTripRedactsSensitiveFields() {
        auto source = record(42, true);
        source.body =
            R"({"prompt":"hello","authorization":"Bearer source","nested":{"api_key":"source-key","cookie":"source-cookie","seed":7}})";
        source.originalBody = source.body;
        source.modifiedBody = R"({"prompt":"changed","access_token":"source-token"})";
        source.path = "/api/generate?api_key=path-secret&keep=visible";
        source.audit = {"upstream called with ?api_key=audit-secret"};

        QBuffer output;
        QVERIFY(output.open(QIODevice::ReadWrite));
        QString error;
        QVERIFY2(exportRequests(output, {source}, &error), qPrintable(error));
        const auto archiveObject = QJsonDocument::fromJson(output.data().trimmed()).object();
        for (const auto &field : {"body", "originalBody", "modifiedBody"}) {
            const auto archivedBody =
                QByteArray::fromBase64(archiveObject.value(field).toString().toLatin1());
            QVERIFY(!archivedBody.contains("Bearer source"));
            QVERIFY(!archivedBody.contains("source-key"));
            QVERIFY(!archivedBody.contains("source-cookie"));
            QVERIFY(!archivedBody.contains("source-token"));
        }
        QVERIFY(!output.data().contains("path-secret"));
        QVERIFY(!output.data().contains("audit-secret"));

        QVERIFY(output.seek(0));
        std::vector<ObservedRequest> imported;
        QVERIFY2(importRequests(output, imported, &error), qPrintable(error));
        QCOMPARE(imported.size(), std::size_t(1));
        QCOMPARE(imported.front().id, source.id);
        QCOMPARE(imported.front().method, source.method);
        QCOMPARE(imported.front().path, QString("/api/generate?api_key=[REDACTED]&keep=visible"));
        QCOMPARE(imported.front().status, source.status);
        QCOMPARE(imported.front().modified, source.modified);
        QVERIFY(!imported.front().path.contains("path-secret"));
        QVERIFY(imported.front().audit.isEmpty());
        QVERIFY(imported.front().path.contains("keep=visible"));
        QVERIFY(!imported.front().body.contains("source"));
        QVERIFY(!imported.front().originalBody.contains("source"));
        QVERIFY(!imported.front().modifiedBody.contains("source"));
        QVERIFY(imported.front().body.contains("hello"));
        QVERIFY(imported.front().body.contains("seed"));
    }

    void importIsAllOrNothingAndHonorsRecordAndByteBounds() {
        const auto first = record(1);
        const auto second = record(2, true);
        QBuffer source;
        QVERIFY(source.open(QIODevice::ReadWrite));
        QVERIFY(exportRequests(source, {first, second}));
        QVERIFY(source.seek(0));
        auto destination = std::vector<ObservedRequest>{record(99)};
        QString error;
        QVERIFY(!importRequests(source, destination, &error, 1));
        QVERIFY(!error.isEmpty());
        QCOMPARE(destination.size(), std::size_t(1));
        QCOMPARE(destination.front().id, quint64(99));

        QBuffer tooSmall;
        QVERIFY(tooSmall.open(QIODevice::ReadWrite));
        QVERIFY(exportRequests(tooSmall, {first}));
        QVERIFY(tooSmall.seek(0));
        QVERIFY(!importRequests(tooSmall, destination, &error, 10, 1));
        QCOMPARE(destination.size(), std::size_t(1));
        QCOMPARE(destination.front().id, quint64(99));

        QBuffer malformed;
        malformed.setData("{\"id\":1}\nnot-json\n");
        QVERIFY(malformed.open(QIODevice::ReadOnly));
        QVERIFY(!importRequests(malformed, destination, &error));
        QCOMPARE(destination.size(), std::size_t(1));
        QCOMPARE(destination.front().id, quint64(99));
    }

    void summaryCountsBodiesModificationsAndStatuses() {
        auto first = record(1);
        auto second = record(2, true);
        second.status = 201;
        const auto summary = summarizeRequests({first, second});
        QCOMPARE(summary.count, std::size_t(2));
        QCOMPARE(summary.modifiedCount, std::size_t(1));
        QCOMPARE(summary.totalBodyBytes, std::size_t(first.body.size() + second.body.size()));
        QCOMPARE(summary.statusCounts.at(200), std::size_t(1));
        QCOMPARE(summary.statusCounts.at(201), std::size_t(1));
    }

    void offlineReplayPreloadsHistoryWithoutOpeningOrForwardingConnections() {
        ProxyServer proxy;
        const auto first = record(10);
        const auto second = record(11, true);
        QVERIFY(proxy.loadOfflineReplay({first, second}));
        QCOMPARE(proxy.listenPort(), quint16(0));
        QCOMPARE(proxy.history().size(), std::size_t(2));
        QCOMPARE(proxy.history().front().id, first.id);
        QCOMPARE(proxy.history().back().id, second.id);

        QVERIFY(proxy.loadOfflineReplay({record(12)}));
        QCOMPARE(proxy.listenPort(), quint16(0));
        QCOMPARE(proxy.history().size(), std::size_t(1));
        QCOMPARE(proxy.history().front().id, quint64(12));
    }

    void retentionEvictsOldestByCountAndAggregateBodyBudget() {
        if (!loopbackAvailable())
            QSKIP("Loopback sockets are unavailable in this test environment.");
        MockOllama mock;
        ProxyServer proxy;
        ProxyOptions options;
        options.maxHistory = 2;
        options.maxHistoryBytes = 3 * 1024 * 1024;
        options.maxBodyBytes = 4 * 1024 * 1024;
        QVERIFY(proxy.start(configFor(mock), options));
        QTcpSocket client;
        client.connectToHost(QHostAddress::LocalHost, proxy.listenPort());
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        for (int index = 0; index < 3; ++index) {
            const auto body =
                QByteArray("{\"prompt\":\"small-") + QByteArray::number(index) + "\"}";
            client.write("POST /api/generate HTTP/1.1\r\nHost: localhost\r\nContent-Type: "
                         "application/json\r\nContent-Length: " +
                         QByteArray::number(body.size()) + "\r\n\r\n" + body);
            QTRY_COMPARE(mock.bodies.size(), index + 1);
            QTRY_VERIFY(client.bytesAvailable() > 0);
            client.readAll();
        }
        QCOMPARE(proxy.history().size(), std::size_t(2));
        QVERIFY(proxy.history().front().body.contains("small-1"));
        QVERIFY(proxy.history().back().body.contains("small-2"));

        for (int index = 0; index < 2; ++index) {
            const auto body = QByteArray("{\"prompt\":\"large-") +
                              QByteArray(2 * 1024 * 1024, 'x') + QByteArray::number(index) + "\"}";
            client.write("POST /api/generate HTTP/1.1\r\nHost: localhost\r\nContent-Type: "
                         "application/json\r\nContent-Length: " +
                         QByteArray::number(body.size()) + "\r\n\r\n" + body);
            QTRY_COMPARE(mock.bodies.size(), index + 4);
            QTRY_VERIFY(client.bytesAvailable() > 0);
            client.readAll();
        }
        const auto retained = proxy.history();
        QCOMPARE(retained.size(), std::size_t(1));
        QVERIFY(retained.front().body.contains("large-"));
        proxy.stop();
    }

    void guiEventLoopRemainsResponsiveDuringSyntheticRequestLoad() {
        if (!loopbackAvailable())
            QSKIP("Loopback sockets are unavailable in this test environment.");
        MockOllama mock;
        SessionController controller;
        MainWindow window(&controller);
        auto *localDevice = window.findChild<QCheckBox *>("localDeviceInput");
        auto *server = window.findChild<QLineEdit *>("serverIpInput");
        auto *serverPort = window.findChild<QSpinBox *>("serverPortInput");
        auto *listenPort = window.findChild<QSpinBox *>("localListenPortInput");
        auto *historyLimit = window.findChild<QSpinBox *>("historyRecordLimitInput");
        auto *prepare = window.findChild<QPushButton *>("prepareButton");
        auto *start = window.findChild<QPushButton *>("startObserveButton");
        auto *requestList = window.findChild<QListWidget *>("observedRequests");
        QVERIFY(localDevice && server && serverPort && listenPort && historyLimit && prepare &&
                start && requestList);
        QTcpServer reservation;
        QVERIFY(reservation.listen(QHostAddress::LocalHost, 0));
        const auto proxyPort = reservation.serverPort();
        reservation.close();
        localDevice->setChecked(true);
        server->setText("127.0.0.1");
        serverPort->setValue(mock.serverPort());
        listenPort->setValue(proxyPort);
        historyLimit->setValue(300);
        prepare->click();
        QCOMPARE(controller.state(), SessionController::State::Ready);
        start->click();

        QTcpSocket client;
        client.connectToHost(QHostAddress::LocalHost, proxyPort);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        int heartbeats = 0;
        QTimer heartbeat;
        heartbeat.setInterval(5);
        connect(&heartbeat, &QTimer::timeout, this, [&] { ++heartbeats; });
        heartbeat.start();
        constexpr int requestCount = 300;
        for (int index = 0; index < requestCount; ++index) {
            const auto body = QByteArray("{\"prompt\":\"") + QByteArray::number(index) + "\"}";
            client.write("POST /api/generate HTTP/1.1\r\nHost: localhost\r\nContent-Type: "
                         "application/json\r\nContent-Length: " +
                         QByteArray::number(body.size()) + "\r\n\r\n" + body);
            QTRY_COMPARE(mock.bodies.size(), index + 1);
            QTRY_VERIFY(client.bytesAvailable() > 0);
            client.readAll();
        }
        QTRY_VERIFY(heartbeats >= 2);
        QTRY_COMPARE(requestList->count(), requestCount);
        QCOMPARE(controller.state(), SessionController::State::Ready);
        window.close();
    }
};

QTEST_MAIN(M5InspectionTests)
#include "M5InspectionTests.moc"
