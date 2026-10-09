#include "core/BoundedHistory.hpp"
#include "core/SessionConfig.hpp"
#include "gui/MainWindow.hpp"
#include "session/SessionController.hpp"

#include <QComboBox>
#include <QLineEdit>
#include <QNetworkInterface>
#include <QPushButton>
#include <QSet>
#include <QSignalSpy>
#include <QSpinBox>
#include <QtTest>

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
};

QTEST_MAIN(M1FoundationTests)
#include "M1FoundationTests.moc"
