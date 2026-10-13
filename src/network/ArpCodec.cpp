#include "ArpCodec.hpp"
#include <QHostAddress>
namespace interceptor {
namespace {
quint16 word(const QByteArray &bytes, int offset) {
    return (static_cast<quint16>(static_cast<unsigned char>(bytes[offset])) << 8) |
           static_cast<unsigned char>(bytes[offset + 1]);
}
void putWord(QByteArray &bytes, quint16 value) {
    bytes.append(static_cast<char>(value >> 8));
    bytes.append(static_cast<char>(value & 255));
}
QString address(const QByteArray &bytes, int offset) {
    quint32 value = 0;
    for (int i = 0; i < 4; ++i)
        value = (value << 8) | static_cast<unsigned char>(bytes[offset + i]);
    return QHostAddress(value).toString();
}
bool putAddress(QByteArray &bytes, const QString &text) {
    QHostAddress value;
    if (!value.setAddress(text) || value.protocol() != QAbstractSocket::IPv4Protocol)
        return false;
    const auto ip = value.toIPv4Address();
    for (int shift = 24; shift >= 0; shift -= 8)
        bytes.append(static_cast<char>((ip >> shift) & 255));
    return true;
}
} // namespace
std::optional<ArpPacket> ArpCodec::parse(const QByteArray &bytes, QString *error) {
    const auto fail = [error](const QString &message) -> std::optional<ArpPacket> {
        if (error)
            *error = message;
        return std::nullopt;
    };
    if (error)
        error->clear();
    if (bytes.size() < 14)
        return fail("Truncated Ethernet header");
    if (word(bytes, 12) != 0x0806)
        return fail("Unsupported Ethernet type (VLAN frames are not decoded)");
    if (bytes.size() < 42)
        return fail("Truncated Ethernet/IPv4 ARP packet");
    if (word(bytes, 14) != 1 || word(bytes, 16) != 0x0800 ||
        static_cast<unsigned char>(bytes[18]) != 6 || static_cast<unsigned char>(bytes[19]) != 4)
        return fail("Unsupported ARP hardware/protocol/address sizes");
    const auto operation = word(bytes, 20);
    if (operation != 1 && operation != 2)
        return fail("Unsupported ARP operation");
    ArpPacket packet{bytes.mid(6, 6),    bytes.mid(0, 6),    bytes.mid(22, 6), bytes.mid(32, 6),
                     address(bytes, 28), address(bytes, 38), operation};
    return packet;
}
QByteArray ArpCodec::encode(const ArpPacket &packet, QString *error) {
    const auto fail = [error](const QString &message) {
        if (error)
            *error = message;
        return QByteArray();
    };
    if (error)
        error->clear();
    if (packet.ethernetSource.size() != 6 || packet.ethernetDestination.size() != 6 ||
        packet.senderMac.size() != 6 || packet.targetMac.size() != 6)
        return fail("MAC addresses must contain exactly six bytes");
    if (packet.operation != 1 && packet.operation != 2)
        return fail("Unsupported ARP operation");
    QByteArray bytes;
    bytes.reserve(60);
    bytes.append(packet.ethernetDestination);
    bytes.append(packet.ethernetSource);
    putWord(bytes, 0x0806);
    putWord(bytes, 1);
    putWord(bytes, 0x0800);
    bytes.append(char(6));
    bytes.append(char(4));
    putWord(bytes, packet.operation);
    bytes.append(packet.senderMac);
    if (!putAddress(bytes, packet.senderIp))
        return fail("Sender IPv4 required");
    bytes.append(packet.targetMac);
    if (!putAddress(bytes, packet.targetIp))
        return fail("Target IPv4 required");
    bytes.append(QByteArray(60 - bytes.size(), char(0)));
    return bytes;
}
} // namespace interceptor
