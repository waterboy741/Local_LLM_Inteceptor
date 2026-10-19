#include "MockOllama.hpp"
#include "core/BoundedHistory.hpp"
#include "core/SessionConfig.hpp"
#include "gui/MainWindow.hpp"
#include "session/SessionController.hpp"

#include <QCheckBox>
#include <QComboBox>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QNetworkInterface>
#include <QPushButton>
#include <QRegularExpression>
#include <QScrollBar>
#include <QSet>
#include <QSignalSpy>
#include <QSpinBox>
#include <QTabWidget>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTextEdit>
#include <QtTest>

#include <memory>
#include <stdexcept>

using namespace interceptor;

class M1FoundationTests : public QObject {
    Q_OBJECT

  private:
    static SessionConfig validConfig() {
        SessionConfig config;
        config.interfaceName = "synthetic0";
        config.clientIp = "192.0.2.10";
        config.serverIp = "198.51.100.30";
        config.serverPort = 18081;
        return config;
    }

  private slots:
    void configurableDestination() {
        auto config = validConfig();
        QVERIFY(config.validate().isEmpty());
        config.serverIp = "203.0.113.50";
        config.serverPort = 65535;
        QVERIFY(config.validate().isEmpty());
        config.serverPort = 1;
        QVERIFY(config.validate().isEmpty());
    }

    void invalidTargets() {
        auto config = validConfig();
        config.interfaceName.clear();
        QVERIFY(!config.validate().isEmpty());
        for (const auto &address :
             {"", "not-an-ip", "::1", "0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255"}) {
            config = validConfig();
            config.clientIp = address;
            QVERIFY2(!config.validate().isEmpty(), address);
            config = validConfig();
            config.serverIp = address;
            QVERIFY2(!config.validate().isEmpty(), address);
        }
        config = validConfig();
        config.serverIp = config.clientIp;
        QVERIFY(!config.validate().isEmpty());
        for (const auto port : {-1, 0, 65536}) {
            config = validConfig();
            config.serverPort = port;
            QVERIFY(!config.validate().isEmpty());
        }
        config = validConfig();
        config.apiPaths = {"api/generate"};
        QVERIFY(!config.validate().isEmpty());
    }

    void explicitProxyAllowsSameDeviceWithoutNetworkInterface() {
        auto config = validConfig();
        config.explicitProxy = true;
        config.interfaceName.clear();
        config.clientIp = "127.0.0.1";
        config.serverIp = "127.0.0.1";
        QVERIFY(config.validate().isEmpty());
        SessionController controller;
        QVERIFY(controller.prepare(config));
        QCOMPARE(controller.config()->clientIp, QString("127.0.0.1"));
        QCOMPARE(controller.config()->serverIp, QString("127.0.0.1"));
        QVERIFY(controller.config()->interfaceName.isEmpty());
        config.explicitProxy = false;
        QVERIFY(!config.validate().isEmpty());
    }

    void localDeviceGuiPreparesWithoutInterfaceOrSeparateClient() {
        SessionController controller;
        MainWindow window(&controller);
        auto *local = window.findChild<QCheckBox *>("localDeviceInput");
        auto *interfaces = window.findChild<QComboBox *>("interfaceInput");
        auto *client = window.findChild<QLineEdit *>("clientIpInput");
        auto *server = window.findChild<QLineEdit *>("serverIpInput");
        auto *listenPort = window.findChild<QSpinBox *>("localListenPortInput");
        auto *prepare = window.findChild<QPushButton *>("prepareButton");
        QVERIFY(local && interfaces && client && server && listenPort && prepare);
        server->clear();
        local->setChecked(true);
        QCOMPARE(server->text(), QString("127.0.0.1"));
        QCOMPARE(listenPort->value(), 0);
        QVERIFY(!interfaces->isEnabled());
        QVERIFY(!client->isEnabled());
        interfaces->clear();
        client->clear();
        server->setText("127.0.0.1");
        prepare->click();
        QCOMPARE(controller.state(), SessionController::State::Ready);
        QVERIFY(controller.config().has_value());
        QVERIFY(controller.config()->explicitProxy);
        QCOMPARE(controller.config()->clientIp, QString("127.0.0.1"));
        QCOMPARE(controller.config()->serverIp, QString("127.0.0.1"));
        QVERIFY(controller.config()->interfaceName.isEmpty());
        QVERIFY(!local->isEnabled());
        controller.stop();
        QVERIFY(local->isEnabled());
        QVERIFY(!client->isEnabled());
        local->setChecked(false);
        QVERIFY(client->isEnabled());
    }

    void localClientCanUseRemoteUpstreamOnTheSamePort() {
        auto config = validConfig();
        config.interfaceName = "lo0";
        config.clientIp = "127.0.0.1";
        config.serverIp = "192.168.1.141";
        config.serverPort = 11434;
        config.explicitProxy = true;
        QVERIFY(config.validate().isEmpty());
        SessionController controller;
        QVERIFY(controller.prepare(config));
        QCOMPARE(controller.config()->serverPort, 11434);
    }

    void loopbackClientGuiAcceptsRemoteUpstreamOnSamePort() {
        SessionController controller;
        MainWindow window(&controller);
        auto *interfaces = window.findChild<QComboBox *>("interfaceInput");
        auto *client = window.findChild<QLineEdit *>("clientIpInput");
        auto *server = window.findChild<QLineEdit *>("serverIpInput");
        auto *port = window.findChild<QSpinBox *>("serverPortInput");
        auto *listenPort = window.findChild<QSpinBox *>("localListenPortInput");
        auto *local = window.findChild<QCheckBox *>("localDeviceInput");
        auto *prepare = window.findChild<QPushButton *>("prepareButton");
        QVERIFY(interfaces && client && server && port && listenPort && local && prepare);
        QVERIFY(!local->isChecked());
        interfaces->clear();
        interfaces->addItem(QString("lo0"), QVariant(QString("lo0")));
        interfaces->setCurrentIndex(0);
        QCOMPARE(interfaces->currentData().toString(), QString("lo0"));
        client->setText("127.0.0.1");
        server->setText("192.168.1.141");
        port->setValue(11434);
        listenPort->setValue(11434);
        prepare->click();
        QCOMPARE(controller.state(), SessionController::State::Ready);
        QCOMPARE(controller.config()->interfaceName, QString("lo0"));
        QCOMPARE(controller.config()->serverIp, QString("192.168.1.141"));
        controller.stop();
        server->setText("127.0.0.1");
        prepare->click();
        QCOMPARE(controller.state(), SessionController::State::Idle);
        QVERIFY(!controller.config().has_value());
    }

    void preparationUsesIndependentSnapshot() {
        SessionController controller;
        QCOMPARE(controller.state(), SessionController::State::Idle);
        QVERIFY(!controller.config().has_value());
        auto config = validConfig();
        QVERIFY(controller.prepare(config));
        QCOMPARE(controller.state(), SessionController::State::Ready);
        config.serverPort = 12345;
        config.serverIp = "203.0.113.60";
        QVERIFY(controller.config().has_value());
        QCOMPARE(controller.config()->serverPort, 18081);
        QCOMPARE(controller.config()->serverIp, QString("198.51.100.30"));
        QVERIFY(!controller.prepare(config));
        QCOMPARE(controller.config()->serverPort, 18081);
    }

    void invalidPreparationAndIdempotentStop() {
        SessionController controller;
        QSignalSpy changes(&controller, &SessionController::stateChanged);
        auto config = validConfig();
        config.serverPort = 0;
        QVERIFY(!controller.prepare(config));
        QCOMPARE(controller.state(), SessionController::State::Idle);
        QVERIFY(!controller.config().has_value());
        QCOMPARE(changes.count(), 0);
        controller.stop();
        QCOMPARE(changes.count(), 0);
        QVERIFY(controller.prepare(validConfig()));
        controller.stop();
        QCOMPARE(controller.state(), SessionController::State::Idle);
        QVERIFY(!controller.config().has_value());
        QCOMPARE(changes.count(), 3);
        QCOMPARE(changes.at(0).at(0).value<SessionController::State>(),
                 SessionController::State::Ready);
        QCOMPARE(changes.at(1).at(0).value<SessionController::State>(),
                 SessionController::State::Stopping);
        QCOMPARE(changes.at(2).at(0).value<SessionController::State>(),
                 SessionController::State::Idle);
        const auto count = changes.count();
        controller.stop();
        QCOMPARE(changes.count(), count);
        QVERIFY(controller.prepare(validConfig()));
    }

    void boundedHistoryEvictsOldestAndOwnsSnapshots() {
        QVERIFY_THROWS_EXCEPTION(std::invalid_argument, BoundedHistory(0));
        BoundedHistory history(2);
        history.append({1, "first"});
        history.append({2, "second"});
        auto snapshot = history.snapshot();
        history.append({3, "third"});
        QCOMPARE(history.size(), std::size_t(2));
        QCOMPARE(snapshot.front().id, quint64(1));
        QCOMPARE(history.snapshot().front().id, quint64(2));
        QCOMPARE(history.snapshot().back().id, quint64(3));
        snapshot.front().summary = "changed copy";
        QCOMPARE(history.snapshot().front().summary, QString("second"));
        history.clear();
        QCOMPARE(history.size(), std::size_t(0));
        QVERIFY(history.snapshot().empty());
        history.append({4, "after clear"});
        QCOMPARE(history.snapshot().front().id, quint64(4));
    }

    void boundedHistoryLimitsMetadata() {
        BoundedHistory history(1);
        history.append({1, QString(10000, QChar('x'))});
        QCOMPARE(history.snapshot().front().summary.size(), qsizetype(4096));
    }

    void offscreenWindowStartsIdleAndStopsOnClose() {
        SessionController controller;
        MainWindow window(&controller);
        window.show();
        QCoreApplication::processEvents();
        QVERIFY(window.isVisible());
        QCOMPARE(controller.state(), SessionController::State::Idle);
        QVERIFY(!controller.config().has_value());
        QVERIFY(controller.prepare(validConfig()));
        QVERIFY(window.close());
        QCoreApplication::processEvents();
        QVERIFY(!window.isVisible());
        QCOMPARE(controller.state(), SessionController::State::Idle);
        QVERIFY(!controller.config().has_value());
    }

    void interfaceChoicesUseAvailableCanonicalNames() {
        SessionController controller;
        MainWindow window(&controller);
        auto *interfaces = window.findChild<QComboBox *>("interfaceInput");
        QVERIFY(interfaces);
        QVERIFY(!interfaces->isEditable());
        QSet<QString> expected;
        for (const auto &interface : QNetworkInterface::allInterfaces())
            expected.insert(interface.name());
        QSet<QString> actual;
        for (int index = 0; index < interfaces->count(); ++index) {
            const auto name = interfaces->itemData(index).toString();
            QVERIFY(!name.isEmpty());
            QVERIFY(!interfaces->itemText(index).isEmpty());
            actual.insert(name);
        }
        QCOMPARE(actual, expected);
        QCOMPARE(interfaces->count(), expected.size());
        if (expected.isEmpty()) {
            auto *prepare = window.findChild<QPushButton *>("prepareButton");
            QVERIFY(prepare);
            QVERIFY(!prepare->isEnabled());
        }
        QCOMPARE(controller.state(), SessionController::State::Idle);
    }

    void selectedInterfaceAndPlainPortPrepareConfiguration() {
        SessionController controller;
        MainWindow window(&controller);
        auto *interfaces = window.findChild<QComboBox *>("interfaceInput");
        auto *client = window.findChild<QLineEdit *>("clientIpInput");
        auto *server = window.findChild<QLineEdit *>("serverIpInput");
        auto *port = window.findChild<QSpinBox *>("serverPortInput");
        auto *prepare = window.findChild<QPushButton *>("prepareButton");
        auto *refresh = window.findChild<QPushButton *>("refreshInterfacesButton");
        QVERIFY(interfaces && client && server && port && prepare && refresh);
        QCOMPARE(port->buttonSymbols(), QAbstractSpinBox::NoButtons);
        QCOMPARE(port->minimum(), 1);
        QCOMPARE(port->maximum(), 65535);
        if (interfaces->count() == 0)
            QSKIP("No interfaces available for selection; empty-list behavior checked separately.");
        interfaces->setCurrentIndex(interfaces->count() - 1);
        const auto selectedName = interfaces->currentData().toString();
        refresh->click();
        QCOMPARE(interfaces->currentData().toString(), selectedName);
        client->setText("192.0.2.10");
        server->setText("198.51.100.30");
        port->setValue(18081);
        prepare->click();
        QCOMPARE(controller.state(), SessionController::State::Ready);
        QVERIFY(controller.config().has_value());
        QCOMPARE(controller.config()->interfaceName, selectedName);
        QCOMPARE(controller.config()->serverPort, 18081);
        QVERIFY(!interfaces->isEnabled());
        QVERIFY(!port->isEnabled());
        QVERIFY(!refresh->isEnabled());
        controller.stop();
        QVERIFY(interfaces->isEnabled());
        QVERIFY(port->isEnabled());
        QVERIFY(refresh->isEnabled());
    }

    void emptyInterfaceSelectionCannotPrepare() {
        SessionController controller;
        MainWindow window(&controller);
        auto *interfaces = window.findChild<QComboBox *>("interfaceInput");
        auto *client = window.findChild<QLineEdit *>("clientIpInput");
        auto *server = window.findChild<QLineEdit *>("serverIpInput");
        auto *prepare = window.findChild<QPushButton *>("prepareButton");
        QVERIFY(interfaces && client && server && prepare);
        interfaces->clear();
        client->setText("192.0.2.10");
        server->setText("198.51.100.30");
        prepare->click();
        QCOMPARE(controller.state(), SessionController::State::Idle);
        QVERIFY(!controller.config().has_value());
    }

    void observeRequestsAppearWithExactDetailsAndCloseStopsRelay() {
        QTcpServer mock;
        QVERIFY(mock.listen(QHostAddress::LocalHost, 0));
        int requestsReceived = 0;
        connect(&mock, &QTcpServer::newConnection, this, [&] {
            while (mock.hasPendingConnections()) {
                auto *socket = mock.nextPendingConnection();
                auto pending = std::make_shared<QByteArray>();
                connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
                connect(socket, &QTcpSocket::readyRead, this, [&, socket, pending] {
                    pending->append(socket->readAll());
                    const auto split = pending->indexOf("\r\n\r\n");
                    if (split < 0)
                        return;
                    qint64 length = 0;
                    for (const auto &line : pending->left(split).split('\n'))
                        if (line.trimmed().toLower().startsWith("content-length:"))
                            length = line.mid(line.indexOf(':') + 1).trimmed().toLongLong();
                    if (pending->size() < split + 4 + length)
                        return;
                    ++requestsReceived;
                    pending->remove(0, split + 4 + length);
                    socket->write("HTTP/1.1 200 OK\r\nContent-Type: "
                                  "application/json\r\nContent-Length: 2\r\n\r\n{}");
                });
            }
        });
        SessionController controller;
        MainWindow window(&controller);
        auto *start = window.findChild<QPushButton *>("startObserveButton");
        auto *listenPort = window.findChild<QSpinBox *>("localListenPortInput");
        auto *status = window.findChild<QLabel *>("sessionStatus");
        auto *list = window.findChild<QListWidget *>("observedRequests");
        auto *details = window.findChild<QTextEdit *>("requestDetails");
        QVERIFY(start && listenPort && status && list && details);
        QVERIFY(!start->isEnabled());
        QCOMPARE(list->count(), 0);
        listenPort->setValue(0);
        auto config = validConfig();
        config.serverIp = "127.0.0.1";
        config.serverPort = mock.serverPort();
        config.explicitProxy = true;
        QVERIFY(controller.prepare(config));
        QVERIFY(start->isEnabled());
        start->click();
        const auto endpoint =
            QRegularExpression("http://127\\.0\\.0\\.1:(\\d+)").match(status->text());
        QVERIFY2(endpoint.hasMatch(), qPrintable(status->text()));
        QTcpSocket client;
        client.connectToHost(QHostAddress::LocalHost, endpoint.captured(1).toUShort());
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        const QByteArray body = " { \"prompt\": \"synthetic GUI request\" } ";
        const auto request = [&](const QByteArray &path) {
            return "POST " + path +
                   " HTTP/1.1\r\nHost: example\r\nContent-Type: "
                   "application/json\r\nContent-Length: " +
                   QByteArray::number(body.size()) + "\r\n\r\n" + body;
        };
        client.write(request("/api/generate"));
        QTRY_COMPARE(list->count(), 1);
        list->setCurrentRow(0);
        QCOMPARE(details->toPlainText(),
                 QString::fromUtf8(QJsonDocument::fromJson(body).toJson(QJsonDocument::Indented)));
        QVERIFY(list->item(0)->text().contains("POST /api/generate"));
        QVERIFY(list->item(0)->text().contains("200"));
        client.readAll();
        client.write(request("/nonmatching"));
        QTRY_COMPARE(requestsReceived, 2);
        QTRY_VERIFY(client.peek(client.bytesAvailable()).contains("{}"));
        QTest::qWait(300);
        QCOMPARE(list->count(), 1);
        QCOMPARE(details->toPlainText(),
                 QString::fromUtf8(QJsonDocument::fromJson(body).toJson(QJsonDocument::Indented)));
        window.close();
        QTRY_COMPARE(client.state(), QAbstractSocket::UnconnectedState);
        QCOMPARE(controller.state(), SessionController::State::Idle);
        QCOMPARE(list->count(), 0);
        QVERIFY(details->toPlainText().isEmpty());
    }

    void openAiCompatiblePathIsIncludedInDefaults() {
        const SessionConfig config;
        QVERIFY(config.apiPaths.contains("/v1/chat/completions"));
        SessionController controller;
        MainWindow window(&controller);
        auto *paths = window.findChild<QLineEdit *>("apiPathsInput");
        QVERIFY(paths);
        QVERIFY(paths->text().split(',').contains("/v1/chat/completions"));
        auto *tabs = window.findChild<QTabWidget *>();
        auto *requests = window.findChild<QListWidget *>("observedRequests");
        QVERIFY(tabs && requests);
        QCOMPARE(tabs->tabText(0), QString("Configuration"));
        QCOMPARE(tabs->tabText(1), QString("Requests"));
        QVERIFY(tabs->widget(0)->isAncestorOf(paths));
        QVERIFY(tabs->widget(1)->isAncestorOf(requests));
    }

    void oversizedAndDeepJsonDetailsUseBoundedRawFallback() {
        SessionController controller;
        MainWindow window(&controller);
        auto *list = window.findChild<QListWidget *>("observedRequests");
        auto *details = window.findChild<QTextEdit *>("requestDetails");
        QVERIFY(list && details);
        const auto show = [&](quint64 id, const QByteArray &body) {
            auto *item = new QListWidgetItem("Synthetic resource-bound record", list);
            item->setData(Qt::UserRole, id);
            item->setData(Qt::UserRole + 1, body);
            list->setCurrentItem(item);
        };
        QByteArray deep = "{\"nested\":";
        deep += QByteArray(128, '[') + "0" + QByteArray(128, ']') + '}';
        QVERIFY(!QJsonDocument::fromJson(deep).isNull());
        show(1001, deep);
        QCOMPARE(details->toPlainText(), QString::fromUtf8(deep));
        const QByteArray large = "{\"content\":\"" + QByteArray(600 * 1024, 'x') + "\"}";
        QVERIFY(!QJsonDocument::fromJson(large).isNull());
        show(1002, large);
        QCOMPARE(details->toPlainText(), QString::fromUtf8(large));
        const QByteArray shallow = "{\"text\":\"brackets [ and { inside strings\"}";
        show(1003, shallow);
        QCOMPARE(details->toPlainText(), QString::fromUtf8(QJsonDocument::fromJson(shallow).toJson(
                                             QJsonDocument::Indented)));
        list->setCurrentRow(-1);
        QVERIFY(details->toPlainText().isEmpty());
    }

    void requestDetailsStayScrolledAndPrettyPrintingPreservesRawBodies() {
        MockOllama mock;
        SessionController controller;
        MainWindow window(&controller);
        window.resize(1100, 700);
        window.show();
        window.findChild<QTabWidget *>()->setCurrentIndex(1);
        auto *start = window.findChild<QPushButton *>("startObserveButton");
        auto *listenPort = window.findChild<QSpinBox *>("localListenPortInput");
        auto *status = window.findChild<QLabel *>("sessionStatus");
        auto *list = window.findChild<QListWidget *>("observedRequests");
        auto *details = window.findChild<QTextEdit *>("requestDetails");
        auto *messages = window.findChild<QListWidget *>("messageItems");
        auto *messageDetails = window.findChild<QTextEdit *>("messageDetails");
        QVERIFY(start && listenPort && status && list && details && messages && messageDetails);
        listenPort->setValue(0);
        auto config = validConfig();
        config.serverIp = "127.0.0.1";
        config.serverPort = mock.serverPort();
        config.explicitProxy = true;
        config.apiPaths = {"/v1/chat/completions"};
        QVERIFY(controller.prepare(config));
        start->click();
        const auto endpoint =
            QRegularExpression("http://127\\.0\\.0\\.1:(\\d+)").match(status->text());
        QVERIFY2(endpoint.hasMatch(), qPrintable(status->text()));
        QTcpSocket client;
        client.connectToHost(QHostAddress::LocalHost, endpoint.captured(1).toUShort());
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        const auto send = [&](const QByteArray &body) {
            client.write("POST /v1/chat/completions HTTP/1.1\r\nHost: ignored\r\n"
                         "Content-Type: application/json\r\nContent-Length: " +
                         QByteArray::number(body.size()) + "\r\n\r\n" + body);
        };
        QByteArray body = " {\"messages\":[";
        for (int index = 0; index < 180; ++index) {
            if (index)
                body += ',';
            body += "{\"role\":\"user\",\"content\":\"message " + QByteArray::number(index) + "\"}";
        }
        body += "]} ";
        send(body);
        QTRY_COMPARE(mock.bodies.size(), 1);
        QCOMPARE(mock.bodies.front(), body);
        QTRY_COMPARE(list->count(), 1);
        list->setCurrentRow(0);
        const auto pretty = QJsonDocument::fromJson(body).toJson(QJsonDocument::Indented);
        QCOMPARE(details->toPlainText(), QString::fromUtf8(pretty));
        QCOMPARE(messages->count(), 180);
        QVERIFY(messages->item(0)->text().contains("message 0"));
        QVERIFY(messages->item(179)->text().contains("message 179"));
        messages->setCurrentRow(179);
        QVERIFY(messageDetails->toPlainText().contains("message 179"));
        QCOMPARE(list->item(0)->data(Qt::UserRole + 1).toByteArray(), body);
        QTRY_VERIFY(details->verticalScrollBar()->maximum() > 0);
        details->verticalScrollBar()->setValue(details->verticalScrollBar()->maximum() / 2);
        const int position = details->verticalScrollBar()->value();
        QVERIFY(position > 0);
        messages->setCurrentRow(0);
        QVERIFY(messageDetails->toPlainText().contains("message 0"));
        QCOMPARE(details->verticalScrollBar()->value(), position);
        messages->setCurrentRow(179);
        QTest::qWait(850);
        QCOMPARE(details->verticalScrollBar()->value(), position);
        QCOMPARE(details->toPlainText(), QString::fromUtf8(pretty));
        QCOMPARE(messages->count(), 180);
        QCOMPARE(messages->currentRow(), 179);
        client.readAll();
        const QByteArray second = " {\"prompt\":\"another request\"} ";
        send(second);
        QTRY_COMPARE(mock.bodies.size(), 2);
        QCOMPARE(mock.bodies.back(), second);
        QTRY_COMPARE(list->count(), 2);
        QTest::qWait(550);
        QCOMPARE(list->currentRow(), 0);
        QCOMPARE(details->verticalScrollBar()->value(), position);
        QCOMPARE(details->toPlainText(), QString::fromUtf8(pretty));
        QCOMPARE(messages->count(), 180);
        QCOMPARE(messages->currentRow(), 179);
        QCOMPARE(list->item(0)->data(Qt::UserRole + 1).toByteArray(), body);
        const QByteArray invalid = " {\"broken\": ] ";
        // Invalid JSON is deliberately not retained by the relay. Inject a display
        // record to exercise the viewer fallback without changing that policy.
        auto *malformed = new QListWidgetItem("Synthetic malformed record", list);
        malformed->setData(Qt::UserRole, qulonglong(999999));
        malformed->setData(Qt::UserRole + 1, invalid);
        list->setCurrentItem(malformed);
        QCOMPARE(details->toPlainText(), QString::fromUtf8(invalid));
        QCOMPARE(messages->count(), 0);
        QVERIFY(messageDetails->toPlainText().isEmpty());
        list->setCurrentRow(1);
        QCOMPARE(messages->count(), 0);
        QVERIFY(messageDetails->toPlainText().isEmpty());
        QCOMPARE(details->toPlainText(), QString::fromUtf8(QJsonDocument::fromJson(second).toJson(
                                             QJsonDocument::Indented)));
        window.close();
    }

    void modifyControlsHoldValidatePreserveEditorAndDisplayAudit() {
        MockOllama mock;
        SessionController controller;
        MainWindow window(&controller);
        auto *mode = window.findChild<QComboBox *>("interceptionModeInput");
        auto *hold = window.findChild<QCheckBox *>("holdMatchingInput");
        auto *rules = window.findChild<QTextEdit *>("rulesInput");
        auto *apply = window.findChild<QPushButton *>("applyModificationOptionsButton");
        auto *start = window.findChild<QPushButton *>("startObserveButton");
        auto *listenPort = window.findChild<QSpinBox *>("localListenPortInput");
        auto *status = window.findChild<QLabel *>("sessionStatus");
        auto *held = window.findChild<QListWidget *>("heldRequests");
        auto *originalView = window.findChild<QTextEdit *>("heldOriginalBody");
        auto *editor = window.findChild<QTextEdit *>("heldBodyEditor");
        auto *forward = window.findChild<QPushButton *>("forwardEditedButton");
        auto *history = window.findChild<QListWidget *>("observedRequests");
        auto *diff = window.findChild<QTextEdit *>("modificationDiff");
        QVERIFY(mode && hold && rules && apply && start && listenPort && status && held &&
                originalView && editor && forward && history && diff);
        QCOMPARE(mode->currentIndex(), 0);
        mode->setCurrentIndex(1);
        hold->setChecked(true);
        rules->setPlainText("[{\"id\":\"gui-proposal\",\"path\":\"/api/"
                            "generate\",\"fieldPath\":[\"prompt\"],\"value\":\"rule preview\"}]");
        apply->click();
        listenPort->setValue(0);
        auto config = validConfig();
        config.serverIp = "127.0.0.1";
        config.serverPort = mock.serverPort();
        config.explicitProxy = true;
        QVERIFY(controller.prepare(config));
        start->click();
        const auto endpoint =
            QRegularExpression("http://127\\.0\\.0\\.1:(\\d+)").match(status->text());
        QVERIFY2(endpoint.hasMatch(), qPrintable(status->text()));
        QTcpSocket client;
        client.connectToHost(QHostAddress::LocalHost, endpoint.captured(1).toUShort());
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        const QByteArray original = " {\"model\":\"fixture\",\"prompt\":\"original\"} ";
        const auto request = [&] {
            return "POST /api/generate HTTP/1.1\r\nHost: synthetic\r\nContent-Type: "
                   "application/json\r\nContent-Length: " +
                   QByteArray::number(original.size()) + "\r\n\r\n" + original;
        };
        client.write(request());
        QTRY_COMPARE(held->count(), 1);
        held->setCurrentRow(0);
        QCOMPARE(originalView->toPlainText(), QString::fromUtf8(original));
        QCOMPARE(
            QJsonDocument::fromJson(editor->toPlainText().toUtf8()).object()["prompt"].toString(),
            QString("rule preview"));
        editor->setPlainText("{");
        forward->click();
        QTest::qWait(300);
        QCOMPARE(held->count(), 1);
        QCOMPARE(mock.bodies.size(), 0);
        QCOMPARE(editor->toPlainText(), QString("{"));
        const QString edited =
            QString::fromUtf8(" {\"model\":\"fixture\",\"prompt\":\"manual café 🤖\"} ");
        editor->setPlainText(edited);
        QTest::qWait(300);
        QCOMPARE(editor->toPlainText(), edited);
        forward->click();
        QTRY_COMPARE(mock.bodies.size(), 1);
        QCOMPARE(mock.bodies.front(), edited.toUtf8());
        QTRY_COMPARE(history->count(), 1);
        QTRY_COMPARE(held->count(), 0);
        history->setCurrentRow(0);
        QVERIFY(diff->toPlainText().contains("manual: edited"));
        QVERIFY(diff->toPlainText().contains("prompt"));
        client.readAll();
        hold->setChecked(false);
        rules->setPlainText("[{\"id\":\"gui-rule\",\"path\":\"/api/"
                            "generate\",\"fieldPath\":[\"model\"],\"value\":\"changed-by-rule\"}]");
        apply->click();
        client.write(request());
        QTRY_COMPARE(mock.bodies.size(), 2);
        QCOMPARE(QJsonDocument::fromJson(mock.bodies.back()).object()["model"].toString(),
                 QString("changed-by-rule"));
        QTRY_VERIFY(client.peek(client.bytesAvailable()).contains("{\"done\":true}"));
        client.readAll();
        hold->setChecked(true);
        apply->click();
        client.write(request());
        QTRY_COMPARE(held->count(), 1);
        QCOMPARE(mock.bodies.size(), 2);
        mode->setCurrentIndex(0);
        apply->click();
        QTRY_COMPARE(mock.bodies.size(), 3);
        QCOMPARE(mock.bodies.back(), original);
        QTRY_COMPARE(held->count(), 0);
        QTRY_COMPARE(history->count(), 3);
        history->setCurrentRow(2);
        QVERIFY(diff->toPlainText().contains("mode Observe: original"));
        QVERIFY(diff->toPlainText().contains("Unmodified"));
        QVERIFY(window.close());
        QTRY_COMPARE(client.state(), QAbstractSocket::UnconnectedState);
        QCOMPARE(controller.state(), SessionController::State::Idle);
    }
};

QTEST_MAIN(M1FoundationTests)
#include "M1FoundationTests.moc"
