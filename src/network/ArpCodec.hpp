#pragma once
#include <QByteArray>
#include <QString>
#include <optional>
namespace interceptor {
struct ArpPacket {
    QByteArray ethernetSource, ethernetDestination, senderMac, targetMac;
    QString senderIp, targetIp;
    quint16 operation = 1;
};
class ArpCodec {
  public:
    static std::optional<ArpPacket> parse(const QByteArray &, QString *error = nullptr);
    static QByteArray encode(const ArpPacket &, QString *error = nullptr);
};
} // namespace interceptor
