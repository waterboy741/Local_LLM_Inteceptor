#pragma once
#include "proxy/ProxyServer.hpp"
#include "session/SessionController.hpp"
#include <QMainWindow>
class QLineEdit;
class QComboBox;
class QSpinBox;
class QLabel;
class QListWidget;
class QTextEdit;
namespace interceptor {
class MainWindow : public QMainWindow {
    Q_OBJECT
  public:
    explicit MainWindow(SessionController *controller, QWidget *parent = nullptr);

  protected:
    void closeEvent(QCloseEvent *event) override;

  private:
    SessionController *controller_;
    QComboBox *interface_;
    QLineEdit *client_, *server_, *paths_;
    QSpinBox *port_;
    QLabel *status_;
    ProxyServer proxy_;
    QSpinBox *listenPort_;
    QListWidget *requests_;
    QTextEdit *details_;
    QListWidget *messageItems_;
    QTextEdit *messageDetails_;
};
} // namespace interceptor
