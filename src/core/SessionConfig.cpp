#include "SessionConfig.hpp"
#include <QRegularExpression>
namespace interceptor {
namespace {
bool validPeer(const QString &value, bool allowLoopback = false) {
    const auto parts = value.split('.');
    if (parts.size() != 4)
        return false;
    int first = -1;
    for (int i = 0; i < 4; ++i) {
        const auto &part = parts[i];
        if (part.isEmpty() || part.size() > 3 || (part.size() > 1 && part.startsWith('0')))
            return false;
        for (auto character : part)
            if (character < QChar('0') || character > QChar('9'))
                return false;
        bool ok = false;
        const int octet = part.toInt(&ok);
        if (!ok || octet > 255)
            return false;
        if (i == 0)
            first = octet;
    }
    return first > 0 && (first != 127 || allowLoopback) && first < 224;
}
} // namespace
QStringList SessionConfig::validate() const {
    QStringList errors;
    static const QRegularExpression interfacePattern("^[A-Za-z][A-Za-z0-9_.:-]{0,63}$");
    if (!interfacePattern.match(interfaceName).hasMatch())
        errors << "Enter a valid interface name.";
    if (!validPeer(clientIp))
        errors << "Enter a usable client unicast IPv4 address.";
    if (!validPeer(serverIp, explicitProxy))
        errors << "Enter a usable server unicast IPv4 address.";
    if (clientIp == serverIp)
        errors << "Client and server addresses must differ.";
    if (serverPort < 1 || serverPort > 65535)
        errors << "Server port must be between 1 and 65535.";
    if (apiPaths.isEmpty())
        errors << "Enter at least one API path.";
    for (const auto &path : apiPaths) {
        if (!path.startsWith('/') || path.contains('?') || path.contains('#') ||
            path.contains(QRegularExpression("[\\s\\x00-\\x1f]"))) {
            errors << "API paths must start with / and contain no whitespace, query, or fragment.";
            break;
        }
    }
    return errors;
}
} // namespace interceptor
