#include "MainWindow.hpp"
#include <QCloseEvent>
#include <QComboBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMenuBar>
#include <QMessageBox>
#include <QNetworkInterface>
#include <QPushButton>
#include <QSpinBox>
#include <QTextEdit>
#include <QTimer>
#include <QVBoxLayout>
namespace interceptor {
MainWindow::MainWindow(SessionController *controller, QWidget *parent)
    : QMainWindow(parent), controller_(controller) {
    Q_ASSERT(controller_);
    setWindowTitle("Local LLM Interceptor");
    auto *panel = new QWidget(this);
    auto *layout = new QVBoxLayout(panel);
    layout->addWidget(
        new QLabel("Prepare configuration, then explicitly start the local Observe proxy.", panel));
    auto *form = new QFormLayout;
    interface_ = new QComboBox(panel);
    interface_->setPlaceholderText("No network interfaces available");
    interface_->setObjectName("interfaceInput");
    client_ = new QLineEdit(panel);
    client_->setObjectName("clientIpInput");
    server_ = new QLineEdit(panel);
    server_->setObjectName("serverIpInput");
    port_ = new QSpinBox(panel);
    port_->setRange(1, 65535);
    port_->setButtonSymbols(QAbstractSpinBox::NoButtons);
    port_->setValue(11434);
    port_->setObjectName("serverPortInput");
    paths_ = new QLineEdit("/api/generate,/api/chat", panel);
    paths_->setObjectName("apiPathsInput");
    auto *interfaceRow = new QWidget(panel);
    auto *interfaceLayout = new QHBoxLayout(interfaceRow);
    interfaceLayout->setContentsMargins(0, 0, 0, 0);
    interfaceLayout->addWidget(interface_);
    auto *refresh = new QPushButton("Refresh", interfaceRow);
    refresh->setObjectName("refreshInterfacesButton");
    interfaceLayout->addWidget(refresh);
    form->addRow("Research interface", interfaceRow);
    form->addRow("Client IPv4", client_);
    form->addRow("LLM IPv4", server_);
    form->addRow("LLM TCP port", port_);
    listenPort_ = new QSpinBox(panel);
    listenPort_->setRange(0, 65535);
    listenPort_->setValue(18080);
    listenPort_->setButtonSymbols(QAbstractSpinBox::NoButtons);
    listenPort_->setSpecialValueText("Automatic");
    form->addRow("Local listen port (127.0.0.1)", listenPort_);
    form->addRow("API paths (comma separated)", paths_);
    layout->addLayout(form);
    auto *prepare = new QPushButton("Prepare configuration", panel);
    prepare->setObjectName("prepareButton");
    prepare->setEnabled(interface_->count() > 0);
    layout->addWidget(prepare);
    auto *stop = new QPushButton("Clear session", panel);
    layout->addWidget(stop);
    status_ = new QLabel(
        interface_->count() == 0
            ? "No network interfaces available. Reopen after an interface becomes available."
            : "Idle — no network changes",
        panel);
    layout->addWidget(status_);
    auto *startProxy = new QPushButton("Start Observe proxy", panel);
    startProxy->setEnabled(false);
    layout->addWidget(startProxy);
    requests_ = new QListWidget(panel);
    requests_->setObjectName("observedRequests");
    layout->addWidget(requests_);
    details_ = new QTextEdit(panel);
    details_->setReadOnly(true);
    details_->setObjectName("requestDetails");
    layout->addWidget(details_);
    auto *poll = new QTimer(this);
    poll->setInterval(250);
    connect(poll, &QTimer::timeout, this, [this] {
        const auto history = proxy_.history();
        const auto selected = requests_->currentItem()
                                  ? requests_->currentItem()->data(Qt::UserRole).toULongLong()
                                  : 0;
        requests_->clear();
        for (const auto &event : history) {
            auto *item = new QListWidgetItem(
                QString("%1 %2 — %3").arg(event.method, event.path).arg(event.status), requests_);
            item->setData(Qt::UserRole, event.id);
            item->setData(Qt::UserRole + 1, event.body);
            if (event.id == selected)
                requests_->setCurrentItem(item);
        }
    });
    poll->start();
    connect(requests_, &QListWidget::currentRowChanged, this, [this](int row) {
        const auto *item = row >= 0 ? requests_->item(row) : nullptr;
        details_->setPlainText(item ? QString::fromUtf8(item->data(Qt::UserRole + 1).toByteArray())
                                    : QString());
    });
    connect(startProxy, &QPushButton::clicked, this, [this, startProxy] {
        const auto config = controller_->config();
        if (!config)
            return;
        ProxyOptions options;
        options.listenPort = listenPort_->value();
        if (proxy_.start(*config, options)) {
            status_->setText(QString("Observe proxy listening at http://127.0.0.1:%1 — set the "
                                     "client Ollama base URL here")
                                 .arg(proxy_.listenPort()));
            startProxy->setEnabled(false);
            listenPort_->setEnabled(false);
        } else
            status_->setText(
                "Could not start the local proxy. Check the selected endpoint and listener port.");
    });
    connect(controller_, &SessionController::stateChanged, this,
            [this, startProxy](SessionController::State state) {
                if (state == SessionController::State::Stopping) {
                    proxy_.stop();
                    requests_->clear();
                    details_->clear();
                }
                startProxy->setEnabled(state == SessionController::State::Ready);
                listenPort_->setEnabled(state == SessionController::State::Idle);
            });
    auto *about = menuBar()->addAction("About / License");
    connect(about, &QAction::triggered, this, [this] {
        QMessageBox::about(this, "Local LLM Interceptor",
                           "Copyright © 2026 waterboy741\nGPL-3.0-only\nSource and license: "
                           "repository LICENSE and docs/LICENSING.md");
    });
    const auto refreshInterfaces = [this, prepare] {
        const QString previous = interface_->currentData().toString();
        interface_->clear();
        for (const auto &networkInterface : QNetworkInterface::allInterfaces()) {
            const QString name = networkInterface.name();
            const QString description = networkInterface.humanReadableName();
            interface_->addItem(description.isEmpty() || description == name
                                    ? name
                                    : description + " (" + name + ")",
                                name);
        }
        const int preserved = interface_->findData(previous);
        if (preserved >= 0)
            interface_->setCurrentIndex(preserved);
        prepare->setEnabled(controller_->state() == SessionController::State::Idle &&
                            interface_->count() > 0);
        status_->setText(
            interface_->count() == 0
                ? "No network interfaces available. Refresh after an interface becomes available."
                : "Idle — no network changes");
    };
    connect(refresh, &QPushButton::clicked, this, refreshInterfaces);
    refreshInterfaces();
    connect(prepare, &QPushButton::clicked, this, [this] {
        SessionConfig config{interface_->currentData().toString(), client_->text(), server_->text(),
                             port_->value(), paths_->text().split(',')};
        config.explicitProxy = true;
        const auto errors = config.validate();
        if (!errors.isEmpty()) {
            status_->setText(errors.join("\n"));
            return;
        }
        if (!controller_->prepare(config))
            status_->setText("Clear the current session before preparing another.");
    });
    connect(stop, &QPushButton::clicked, controller_, &SessionController::stop);
    connect(controller_, &SessionController::stateChanged, this,
            [this, prepare, refresh](SessionController::State state) {
                const bool idle = state == SessionController::State::Idle;
                interface_->setEnabled(idle);
                refresh->setEnabled(idle);
                for (auto *input : {client_, server_, paths_})
                    input->setEnabled(idle);
                port_->setEnabled(idle);
                prepare->setEnabled(idle && interface_->count() > 0);
                status_->setText(idle ? "Idle — no network changes"
                                      : "Configuration prepared — no network changes");
            });
    setCentralWidget(panel);
    resize(680, 660);
}
void MainWindow::closeEvent(QCloseEvent *event) {
    proxy_.stop();
    controller_->stop();
    QMainWindow::closeEvent(event);
}
} // namespace interceptor
