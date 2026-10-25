#include "PfAnchorCleanupVerifier.hpp"

#include <QRegularExpression>

namespace interceptor {
namespace {

bool isAsciiWhitespaceOnly(const QByteArray &output) {
    for (const char byte : output) {
        const auto value = static_cast<unsigned char>(byte);
        if (value != 0x20 && (value < 0x09 || value > 0x0d))
            return false;
    }
    return true;
}

bool hasInvalidControlByte(const QByteArray &output) {
    for (const char byte : output) {
        const auto value = static_cast<unsigned char>(byte);
        if (value < 0x20 && (value < 0x09 || value > 0x0d))
            return true;
        if (value == 0x7f)
            return true;
    }
    return false;
}

PfAnchorCleanupVerification classifyRuleOutput(const QByteArray &output) {
    if (isAsciiWhitespaceOnly(output))
        return PfAnchorCleanupVerification::Empty;
    if (QString::fromUtf8(output).toUtf8() != output || hasInvalidControlByte(output))
        return PfAnchorCleanupVerification::Unknown;

    static const QRegularExpression ruleLine(
        "^\\s*@\\d+\\s+(?:pass|block|match|anchor|rdr|nat|binat|scrub|antispoof)"
        "(?:\\s+.*)?$",
        QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression counterLine(
        "^\\s*(?:\\[\\s*Evaluations:\\s*\\d+\\s+Packets:\\s*\\d+\\s+Bytes:\\s*\\d+"
        "\\s*\\]|Evaluations:\\s*\\d+\\s+Packets:\\s*\\d+\\s+Bytes:\\s*\\d+)\\s*$",
        QRegularExpression::CaseInsensitiveOption);

    const auto lines = QString::fromUtf8(output).split('\n');
    for (const auto &line : lines) {
        if (line.trimmed().isEmpty())
            continue;
        if (ruleLine.match(line).hasMatch() || counterLine.match(line).hasMatch())
            continue;
        return PfAnchorCleanupVerification::Unknown;
    }
    return PfAnchorCleanupVerification::NotEmpty;
}

} // namespace

PfAnchorCleanupVerification
PfCommandAnchorCleanupVerifier::verifyOwnedAnchorEmpty(const SessionSnapshot &snapshot) {
    if (timeoutMs_ < 1 || timeoutMs_ > PfDiagnostics::maximumTimeoutMs)
        return PfAnchorCleanupVerification::Unknown;

    constexpr PfQuery queries[] = {PfQuery::SessionFilterRules, PfQuery::SessionTranslationRules};
    for (const auto query : queries) {
        PfQueryOutput output;
        try {
            output = runner_.query(query, snapshot.anchor(), timeoutMs_, maximumOutputBytes);
        } catch (...) {
            return PfAnchorCleanupVerification::Unknown;
        }

        if (output.status != PfCommandStatus::Completed || output.exitCode != 0)
            return PfAnchorCleanupVerification::Unknown;
        if (output.standardOutput.size() > maximumOutputBytes)
            return PfAnchorCleanupVerification::Unknown;
        const auto classification = classifyRuleOutput(output.standardOutput);
        if (classification != PfAnchorCleanupVerification::Empty)
            return classification;
    }

    return PfAnchorCleanupVerification::Empty;
}

} // namespace interceptor
