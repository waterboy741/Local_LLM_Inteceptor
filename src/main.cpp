#include "gui/MainWindow.hpp"
#include <QApplication>
int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    interceptor::SessionController controller;
    interceptor::MainWindow window(&controller);
    window.show();
    return app.exec();
}
