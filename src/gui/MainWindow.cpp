#include "MainWindow.hpp"
#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMenuBar>
#include <QMessageBox>
#include <QNetworkInterface>
#include <QPushButton>
#include <QSet>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QTabWidget>
#include <QTextEdit>
#include <QTimer>
#include <QVBoxLayout>
#include <functional>
namespace interceptor {
namespace {
QString jsonDiff(const QByteArray &original, const QByteArray &edited) {
    if (original == edited)
        return "No changes";
    if (original.size() > 1048576 || edited.size() > 1048576)
        return "Diff unavailable: edit exceeds the 1 MiB preview limit.";
    const auto before = QJsonDocument::fromJson(original), after = QJsonDocument::fromJson(edited);
    if (!before.isObject() || !after.isObject())
        return "Invalid JSON object — diff unavailable";
    QStringList lines;
    int changes = 0;
    const auto preview = [](const QJsonValue &value) {
        if (value.isUndefined())
            return QString("<missing>");
        auto text =
            QString::fromUtf8(QJsonDocument(QJsonArray{value}).toJson(QJsonDocument::Compact));
        text = text.mid(1, text.size() - 2);
        return text.size() > 1024 ? text.left(1024) + "…" : text;
    };
    std::function<void(const QJsonValue &, const QJsonValue &, QString)> visit;
    visit = [&](const QJsonValue &oldValue, const QJsonValue &newValue, QString path) {
        if (changes >= 64 || oldValue == newValue)
            return;
        if (oldValue.isObject() && newValue.isObject()) {
            const auto oldObject = oldValue.toObject(), newObject = newValue.toObject();
            QSet<QString> keys;
            for (const auto &key : oldObject.keys())
                keys.insert(key);
            for (const auto &key : newObject.keys())
                keys.insert(key);
            auto sorted = keys.values();
            sorted.sort();
            for (auto key : sorted) {
                QString component = key;
                component.replace("~", "~0");
                component.replace("/", "~1");
                visit(oldObject.value(key), newObject.value(key), path + "/" + component);
                if (changes >= 64)
                    break;
            }
            return;
        }
        ++changes;
        lines.append("- " + path + ": " + preview(oldValue));
        lines.append("+ " + path + ": " + preview(newValue));
    };
    visit(before.object(), after.object(), {});
    if (changes >= 64)
        lines.append("Diff preview limited to 64 changes.");
    return lines.join("\n").left(65536);
}
} // namespace

MainWindow::MainWindow(SessionController *controller, QWidget *parent)
    : QMainWindow(parent), controller_(controller) {
    Q_ASSERT(controller_);
    setWindowTitle("llm_interceptor");
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
    listenPort_->setObjectName("localListenPortInput");
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
    status_->setObjectName("sessionStatus");
    layout->addWidget(status_);
    auto *startProxy = new QPushButton("Start Observe proxy", panel);
    startProxy->setObjectName("startObserveButton");
    startProxy->setEnabled(false);
    layout->addWidget(startProxy);
    auto *tabs = new QTabWidget(panel);
    layout->addWidget(tabs);
    auto *requestPage = new QWidget(tabs);
    auto *requestLayout = new QVBoxLayout(requestPage);
    tabs->addTab(requestPage, "Requests");
    requests_ = new QListWidget(requestPage);
    requests_->setObjectName("observedRequests");
    requestLayout->addWidget(requests_);
    details_ = new QTextEdit(panel);
    details_->setReadOnly(true);
    details_->setObjectName("requestDetails");
    requestLayout->addWidget(details_);
    auto *diff = new QTextEdit(requestPage);
    diff->setReadOnly(true);
    diff->setObjectName("modificationDiff");
    requestLayout->addWidget(diff);
    auto *settingsPage = new QWidget(tabs);
    auto *settingsLayout = new QVBoxLayout(settingsPage);
    tabs->addTab(settingsPage, "Modify settings");
    auto *mode = new QComboBox(settingsPage);
    mode->addItems({"Observe", "Modify"});
    mode->setObjectName("interceptionModeInput");
    settingsLayout->addWidget(mode);
    auto *holdMatching = new QCheckBox("Hold matching requests for manual editing", settingsPage);
    holdMatching->setObjectName("holdMatchingInput");
    settingsLayout->addWidget(holdMatching);
    auto *holdSeconds = new QSpinBox(settingsPage);
    holdSeconds->setRange(1, 300);
    holdSeconds->setValue(30);
    holdSeconds->setSuffix(" seconds");
    holdSeconds->setObjectName("holdDeadlineSecondsInput");
    settingsLayout->addWidget(holdSeconds);
    settingsLayout->addWidget(
        new QLabel("Timeout forwards original bytes. Observe releases held originals. Stop cancels "
                   "held requests.\nRules replace existing object fields in order; missing fields "
                   "remain unchanged.",
                   settingsPage));
    auto *rules = new QTextEdit(settingsPage);
    rules->setPlainText("[]");
    rules->setObjectName("rulesInput");
    rules->setPlaceholderText(
        "[{\"id\":\"prompt-rule\",\"path\":\"/api/"
        "generate\",\"fieldPath\":[\"prompt\"],\"value\":\"Synthetic prompt\"}]");
    settingsLayout->addWidget(rules);
    auto *applyMode = new QPushButton("Apply mode and rules", settingsPage);
    applyMode->setObjectName("applyModificationOptionsButton");
    settingsLayout->addWidget(applyMode);
    auto *modeStatus = new QLabel("Active mode: Observe", settingsPage);
    settingsLayout->addWidget(modeStatus);
    const auto applySettings = [this, mode, holdMatching, holdSeconds, rules, modeStatus] {
        const auto ruleBytes = rules->toPlainText().toUtf8();
        if (ruleBytes.size() > 2 * 1048576) {
            modeStatus->setText("Rule configuration exceeds 2 MiB; settings were not applied.");
            return false;
        }
        const auto document = QJsonDocument::fromJson(ruleBytes);
        if (!document.isArray()) {
            modeStatus->setText("Rules must be a JSON array; settings were not applied.");
            return false;
        }
        ModificationOptions options;
        options.mode =
            mode->currentIndex() == 0 ? InterceptionMode::Observe : InterceptionMode::Modify;
        options.holdMatching = holdMatching->isChecked();
        options.holdTimeoutMs = holdSeconds->value() * 1000;
        for (const auto &value : document.array()) {
            if (!value.isObject()) {
                modeStatus->setText("Each rule must be an object.");
                return false;
            }
            const auto object = value.toObject();
            if (object.contains("model") && !object.value("model").isString()) {
                modeStatus->setText("Optional rule model must be a string.");
                return false;
            }
            JsonRule rule;
            rule.id = object.value("id").toString();
            rule.path = object.value("path").toString();
            rule.model = object.value("model").toString();
            rule.value = object.value("value");
            if (!object.value("fieldPath").isArray()) {
                modeStatus->setText("fieldPath must be an array of object field names.");
                return false;
            }
            for (const auto &field : object.value("fieldPath").toArray())
                rule.fieldPath.append(field.toString());
            options.rules.push_back(std::move(rule));
        }
        if (!proxy_.setModificationOptions(options)) {
            modeStatus->setText("Invalid rules or requests are held. Release them, or apply "
                                "Observe to forward originals.");
            return false;
        }
        modeStatus->setText(mode->currentIndex() == 0 ? "Active mode: Observe — no edits"
                                                      : "Active mode: Modify");
        return true;
    };
    connect(applyMode, &QPushButton::clicked, this, [applySettings] { applySettings(); });
    auto *heldPage = new QWidget(tabs);
    auto *heldLayout = new QVBoxLayout(heldPage);
    tabs->addTab(heldPage, "Held requests");
    auto *heldList = new QListWidget(heldPage);
    heldList->setObjectName("heldRequests");
    heldLayout->addWidget(heldList);
    auto *original = new QTextEdit(heldPage);
    original->setReadOnly(true);
    original->setObjectName("heldOriginalBody");
    heldLayout->addWidget(original);
    auto *editor = new QTextEdit(heldPage);
    editor->setObjectName("heldBodyEditor");
    heldLayout->addWidget(editor);
    auto *heldDiff = new QTextEdit(heldPage);
    heldDiff->setReadOnly(true);
    heldDiff->setObjectName("heldModificationDiff");
    heldLayout->addWidget(heldDiff);
    connect(editor, &QTextEdit::textChanged, this, [editor, original, heldDiff] {
        heldDiff->setPlainText(
            jsonDiff(original->toPlainText().toUtf8(), editor->toPlainText().toUtf8()));
    });
    auto *releaseOriginal = new QPushButton("Forward original", heldPage);
    releaseOriginal->setObjectName("forwardOriginalButton");
    heldLayout->addWidget(releaseOriginal);
    auto *releaseEdited = new QPushButton("Validate and forward edit", heldPage);
    releaseEdited->setObjectName("forwardEditedButton");
    heldLayout->addWidget(releaseEdited);
    const auto showHeld = [heldList, original, editor, releaseOriginal, releaseEdited] {
        const auto *item = heldList->currentItem();
        original->setPlainText(item ? QString::fromUtf8(item->data(Qt::UserRole + 1).toByteArray())
                                    : QString());
        editor->setPlainText(item ? QString::fromUtf8(item->data(Qt::UserRole + 2).toByteArray())
                                  : QString());
        releaseOriginal->setEnabled(item);
        releaseEdited->setEnabled(item);
    };
    connect(heldList, &QListWidget::currentRowChanged, this, [showHeld](int) { showHeld(); });
    showHeld();
    connect(releaseOriginal, &QPushButton::clicked, this, [this, heldList] {
        const auto *item = heldList->currentItem();
        if (item && !proxy_.resolveHeld(item->data(Qt::UserRole).toULongLong(), {}, true))
            status_->setText("Request expired or was cancelled.");
    });
    connect(releaseEdited, &QPushButton::clicked, this, [this, heldList, editor] {
        const auto *item = heldList->currentItem();
        if (item && !proxy_.resolveHeld(item->data(Qt::UserRole).toULongLong(),
                                        editor->toPlainText().toUtf8()))
            status_->setText("Edit rejected or request expired. Invalid JSON stays held; forward "
                             "the original to continue.");
    });
    auto *poll = new QTimer(this);
    poll->setInterval(250);
    connect(poll, &QTimer::timeout, this, [this, heldList, showHeld] {
        const auto pending = proxy_.held();
        const auto selectedHeld =
            heldList->currentItem() ? heldList->currentItem()->data(Qt::UserRole).toULongLong() : 0;
        {
            const QSignalBlocker blocker(heldList);
            heldList->clear();
            for (const auto &entry : pending) {
                auto *item = new QListWidgetItem(
                    QString("%1 — %2 ms remaining").arg(entry.path).arg(entry.remainingMs),
                    heldList);
                item->setData(Qt::UserRole, entry.id);
                item->setData(Qt::UserRole + 1, entry.originalBody);
                item->setData(Qt::UserRole + 2, entry.proposedBody);
                if (entry.id == selectedHeld)
                    heldList->setCurrentItem(item);
            }
        }
        if (!heldList->currentItem()) {
            if (heldList->count())
                heldList->setCurrentRow(0);
            else
                showHeld();
        }
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
            item->setData(Qt::UserRole + 2, event.modifiedBody);
            item->setData(Qt::UserRole + 3, event.audit.join("\n"));
            item->setData(Qt::UserRole + 4, event.modified);
            if (event.id == selected)
                requests_->setCurrentItem(item);
        }
    });
    poll->start();
    connect(requests_, &QListWidget::currentRowChanged, this, [this, diff](int row) {
        const auto *item = row >= 0 ? requests_->item(row) : nullptr;
        diff->setPlainText(item ? (item->data(Qt::UserRole + 4).toBool()
                                       ? jsonDiff(item->data(Qt::UserRole + 1).toByteArray(),
                                                  item->data(Qt::UserRole + 2).toByteArray())
                                       : "Unmodified") +
                                      "\nAudit:\n" + item->data(Qt::UserRole + 3).toString()
                                : QString());
        details_->setPlainText(item ? QString::fromUtf8(item->data(Qt::UserRole + 1).toByteArray())
                                    : QString());
    });
    connect(startProxy, &QPushButton::clicked, this, [this, startProxy, applySettings] {
        if (!applySettings())
            return;
        const auto config = controller_->config();
        if (!config)
            return;
        ProxyOptions options;
        options.listenPort = listenPort_->value();
        if (proxy_.start(*config, options)) {
            status_->setText(QString("Local proxy listening at http://127.0.0.1:%1 — set the "
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
        QMessageBox::about(this, "llm_interceptor",
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
