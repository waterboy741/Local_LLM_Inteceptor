#pragma once
#include <QString>
#include <QStringList>
namespace interceptor {
struct SessionConfig {
    QString interfaceName;
    QString clientIp;
    QString serverIp;
    int serverPort = 11434;
    QStringList apiPaths{"/api/generate", "/api/chat"};
    bool explicitProxy = false;
    QStringList validate() const;
};
} // namespace interceptor
