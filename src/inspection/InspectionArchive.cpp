#include "InspectionArchive.hpp"
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QRegularExpression>
#include <QUrl>

namespace interceptor {
namespace {
QString normalizedKey(QString key) {
    key = key.toLower();
    key.remove(QRegularExpression("[^a-z0-9]"));
    return key;
}

bool sensitiveKey(const QString &key) {
    const auto normalized = normalizedKey(key);
    return normalized.contains("authorization") || normalized.contains("token") ||
           normalized.contains("apikey") || normalized.contains("password") ||
           normalized.contains("passwd") || normalized.contains("secret") ||
           normalized.contains("credential") || normalized.contains("cookie") ||
           normalized == "auth" || normalized == "bearer" || normalized == "jwt" ||
           normalized.contains("privatekey") || normalized.contains("sessionkey") ||
           normalized.contains("signature");
}

QString sanitizedText(QString text);

QJsonValue sanitized(const QJsonValue &value, int depth = 0) {
    if (depth > 32)
        return QString("[REDACTED: nesting limit]");
    if (value.isObject()) {
        QJsonObject result;
        const auto object = value.toObject();
        for (auto it = object.begin(); it != object.end(); ++it)
            result.insert(it.key(), sensitiveKey(it.key()) ? QJsonValue("[REDACTED]")
                                                           : sanitized(it.value(), depth + 1));
        return result;
    }
    if (value.isArray()) {
        QJsonArray result;
        for (const auto &item : value.toArray())
            result.append(sanitized(item, depth + 1));
        return result;
    }
    if (value.isString())
        return sanitizedText(value.toString());
    return value;
}

QString sanitizedText(QString text) {
    static const QRegularExpression parameter(R"(([?&])([^=&#]+)=([^&#]*))");
    QString result;
    qsizetype copiedThrough = 0;
    auto matches = parameter.globalMatch(text);
    while (matches.hasNext()) {
        const auto match = matches.next();
        result += text.mid(copiedThrough, match.capturedStart() - copiedThrough);
        auto key = QUrl::fromPercentEncoding(match.captured(2).toUtf8());
        key.replace('+', ' ');
        result += match.captured(1) + match.captured(2) + "=" +
                  (sensitiveKey(key) ? QString("[REDACTED]") : match.captured(3));
        copiedThrough = match.capturedEnd();
    }
    result += text.mid(copiedThrough);
    return result;
}

QByteArray sanitizedBody(const QByteArray &body) {
    if (body.isEmpty())
        return body;
    QJsonParseError error;
    const auto document = QJsonDocument::fromJson(body, &error);
    if (error.error != QJsonParseError::NoError || !document.isObject())
        return R"({"_redacted":"invalid or unsupported JSON body"})";
    return QJsonDocument(sanitized(document.object()).toObject()).toJson(QJsonDocument::Compact);
}

bool supportedBody(const QByteArray &body) {
    if (body.isEmpty())
        return true;
    QJsonParseError error;
    const auto document = QJsonDocument::fromJson(body, &error);
    return error.error == QJsonParseError::NoError && document.isObject();
}

QJsonObject encode(const ObservedRequest &request) {
    // Audit entries may contain user-authored rule IDs or other free text.
    const QJsonArray audit;
    return {{"format", 1},
            {"id", QString::number(request.id)},
            {"method", request.method.left(32)},
            {"path", sanitizedText(request.path).left(4096)},
            {"body", QString::fromLatin1(sanitizedBody(request.body).toBase64())},
            {"status", request.status},
            {"originalBody", QString::fromLatin1(sanitizedBody(request.originalBody).toBase64())},
            {"modifiedBody", QString::fromLatin1(sanitizedBody(request.modifiedBody).toBase64())},
            {"audit", audit},
            {"modified", request.modified}};
}

bool decode(const QJsonObject &object, ObservedRequest &request) {
    if (object.value("format").toInt(-1) != 1 || !object.value("id").isString() ||
        !object.value("method").isString() || !object.value("path").isString() ||
        !object.value("body").isString() || !object.value("originalBody").isString() ||
        !object.value("modifiedBody").isString() || !object.value("status").isDouble() ||
        !object.value("audit").isArray() || !object.value("modified").isBool())
        return false;
    const auto status = object.value("status").toDouble();
    bool idOk = false;
    const auto id = object.value("id").toString().toULongLong(&idOk);
    if (!idOk || status < 0 || status > 999)
        return false;
    request.id = id;
    request.method = object.value("method").toString();
    request.path = object.value("path").toString();
    request.path = sanitizedText(request.path);
    if (object.value("audit").toArray().size() > 64)
        return false;
    for (const auto &entry : object.value("audit").toArray())
        if (!entry.isString() || entry.toString().size() > 4096)
            return false;
    const auto decodeBody = [](const QJsonValue &value, QByteArray &out) {
        const auto encoded = value.toString().toLatin1();
        out = QByteArray::fromBase64(encoded, QByteArray::AbortOnBase64DecodingErrors);
        return out.toBase64() == encoded;
    };
    if (!decodeBody(object.value("body"), request.body) ||
        !decodeBody(object.value("originalBody"), request.originalBody) ||
        !decodeBody(object.value("modifiedBody"), request.modifiedBody))
        return false;
    request.status = static_cast<int>(status);
    // Imported audit text is user-authored and is never needed to inspect/replay the body.
    request.modified = object.value("modified").toBool();
    return request.method.size() <= 32 && request.path.size() <= 4096 &&
           request.audit.size() <= 64 && request.body.size() <= 16 * 1024 * 1024 &&
           request.originalBody.size() <= 16 * 1024 * 1024 &&
           request.modifiedBody.size() <= 16 * 1024 * 1024;
}

bool fail(QString *error, const QString &message) {
    if (error)
        *error = message;
    return false;
}
} // namespace

InspectionSummary summarizeRequests(const std::vector<ObservedRequest> &requests) {
    InspectionSummary summary;
    summary.count = requests.size();
    for (const auto &request : requests) {
        summary.modifiedCount += request.modified ? 1 : 0;
        summary.totalBodyBytes += static_cast<std::size_t>(request.body.size());
        ++summary.statusCounts[request.status];
    }
    return summary;
}

bool exportRequests(QIODevice &device, const std::vector<ObservedRequest> &requests, QString *error,
                    std::size_t maxRecords, std::size_t maxTotalBytes) {
    if (!device.isOpen() || !device.isWritable())
        return fail(error, "Archive destination is not writable.");
    if (requests.size() > maxRecords)
        return fail(error, "Archive has too many records.");
    if (maxRecords > 1000 || maxTotalBytes > 16 * 1024 * 1024)
        return fail(error, "Archive limits exceed the supported maximum.");
    QByteArray archive;
    for (const auto &request : requests) {
        const auto line = QJsonDocument(encode(request)).toJson(QJsonDocument::Compact) + '\n';
        if (static_cast<std::size_t>(archive.size() + line.size()) > maxTotalBytes)
            return fail(error, "Archive exceeds the configured size limit.");
        archive += line;
    }
    if (device.write(archive) != archive.size())
        return fail(error, "Could not write the complete archive.");
    if (error)
        error->clear();
    return true;
}

bool importRequests(QIODevice &device, std::vector<ObservedRequest> &requests, QString *error,
                    std::size_t maxRecords, std::size_t maxTotalBytes) {
    if (!device.isOpen() || !device.isReadable())
        return fail(error, "Archive source is not readable.");
    if (maxRecords > 1000 || maxTotalBytes > 16 * 1024 * 1024)
        return fail(error, "Archive limits exceed the supported maximum.");
    std::vector<ObservedRequest> parsed;
    std::size_t total = 0;
    while (!device.atEnd()) {
        const auto line = device.readLine(16 * 1024 * 1024 + 1);
        total += static_cast<std::size_t>(line.size());
        if (total > maxTotalBytes)
            return fail(error, "Archive exceeds the configured size limit.");
        if (line.size() > 16 * 1024 * 1024)
            return fail(error, "Archive record exceeds the record size limit.");
        if (line.trimmed().isEmpty())
            continue;
        if (parsed.size() >= maxRecords)
            return fail(error, "Archive has too many records.");
        QJsonParseError parseError;
        const auto document = QJsonDocument::fromJson(line.trimmed(), &parseError);
        ObservedRequest request{};
        if (parseError.error != QJsonParseError::NoError || !document.isObject() ||
            !decode(document.object(), request))
            return fail(error, "Archive contains an invalid or unsupported record.");
        // Imported data is sanitized again so hand-written archives receive the same protection.
        request.body = sanitizedBody(request.body);
        request.originalBody = sanitizedBody(request.originalBody);
        request.modifiedBody = sanitizedBody(request.modifiedBody);
        if (!supportedBody(request.body) || !supportedBody(request.originalBody) ||
            !supportedBody(request.modifiedBody))
            return fail(error, "Archive record contains an unsupported request body.");
        parsed.push_back(std::move(request));
    }
    requests = std::move(parsed);
    if (error)
        error->clear();
    return true;
}
} // namespace interceptor
