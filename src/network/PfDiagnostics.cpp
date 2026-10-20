#include "PfDiagnostics.hpp"

#include <QElapsedTimer>
#include <QJsonArray>
#include <QProcess>
#include <QRegularExpression>
#include <QThread>

namespace interceptor {
namespace {
const QString pfctlPath = "/sbin/pfctl";
const QString applicationAnchor = "llm_interceptor";

QString queryName(PfQuery query) {
    switch (query) {
    case PfQuery::Status:
        return "status";
    case PfQuery::MainFilterRules:
        return "main_filter_rules";
    case PfQuery::MainTranslationRules:
        return "main_translation_rules";
    case PfQuery::ApplicationAnchors:
        return "application_anchors";
    case PfQuery::SessionFilterRules:
        return "session_filter_rules";
    case PfQuery::SessionTranslationRules:
        return "session_translation_rules";
    case PfQuery::States:
        return "global_state_candidates";
    }
    return "unknown";
}

QString commandStatusName(PfCommandStatus status) {
    switch (status) {
    case PfCommandStatus::Completed:
        return "completed";
    case PfCommandStatus::PermissionDenied:
        return "permission_denied";
    case PfCommandStatus::TimedOut:
        return "timed_out";
    case PfCommandStatus::OutputLimitExceeded:
        return "output_limit_exceeded";
    case PfCommandStatus::Failed:
        return "failed";
    }
    return "failed";
}

QStringList argumentsFor(PfQuery query, const QString &sessionAnchor) {
    switch (query) {
    case PfQuery::Status:
        return {"-s", "info"};
    case PfQuery::MainFilterRules:
        return {"-sr", "-v"};
    case PfQuery::MainTranslationRules:
        return {"-sn", "-v"};
    case PfQuery::ApplicationAnchors:
        return {"-a", applicationAnchor, "-s", "Anchors", "-v"};
    case PfQuery::SessionFilterRules:
        return {"-a", sessionAnchor, "-sr", "-v"};
    case PfQuery::SessionTranslationRules:
        return {"-a", sessionAnchor, "-sn", "-v"};
    case PfQuery::States:
        return {"-s", "states"};
    }
    return {};
}

bool permissionDeniedText(const QByteArray &text) {
    const auto lower = text.toLower();
    return lower.contains("operation not permitted") || lower.contains("permission denied") ||
           lower.contains("must be root") || lower.contains("requires root");
}

class SystemPfCommandRunner final : public PfCommandRunner {
  public:
    PfQueryOutput query(PfQuery query, const QString &sessionAnchor, int timeoutMs,
                        qsizetype outputLimitBytes) override {
        QElapsedTimer timer;
        timer.start();
        QProcess process;
        process.setProgram(pfctlPath);
        process.setArguments(argumentsFor(query, sessionAnchor));
        process.setProcessChannelMode(QProcess::SeparateChannels);
        process.start();

        PfQueryOutput result;
        if (!process.waitForStarted(timeoutMs))
            return result;

        QByteArray permissionText;
        qsizetype observedBytes = 0;
        bool overflow = false;
        bool timedOut = false;
        auto drain = [&]() {
            const auto stdoutChunk = process.readAllStandardOutput();
            const auto stderrChunk = process.readAllStandardError();
            observedBytes += stdoutChunk.size() + stderrChunk.size();
            if (permissionText.size() < 4096)
                permissionText += stderrChunk.left(4096 - permissionText.size());
            if (observedBytes > outputLimitBytes) {
                overflow = true;
                process.kill();
            } else {
                result.standardOutput += stdoutChunk;
            }
        };

        while (process.state() != QProcess::NotRunning) {
            drain();
            if (overflow)
                break;
            const int remaining = timeoutMs - static_cast<int>(timer.elapsed());
            if (remaining <= 0) {
                timedOut = true;
                process.kill();
                break;
            }
            process.waitForReadyRead(qMin(remaining, 100));
        }
        if (process.state() != QProcess::NotRunning)
            process.waitForFinished(100);
        drain();

        if (overflow) {
            result.status = PfCommandStatus::OutputLimitExceeded;
            result.standardOutput.clear();
            return result;
        }
        if (timedOut) {
            result.status = PfCommandStatus::TimedOut;
            result.standardOutput.clear();
            return result;
        }
        result.exitCode = process.exitCode();
        if (result.exitCode == 0) {
            result.status = PfCommandStatus::Completed;
            return result;
        }
        result.status = permissionDeniedText(permissionText) ? PfCommandStatus::PermissionDenied
                                                             : PfCommandStatus::Failed;
        result.standardOutput.clear();
        return result;
    }
};

bool lineMentionsAttachment(const QByteArray &output, const QByteArray &kind,
                            const QByteArray &anchorPattern) {
    const QRegularExpression expression(
        "\\b" + QString::fromLatin1(kind) + "\\s+[\\\"']" +
        QRegularExpression::escape(QString::fromLatin1(anchorPattern)) + "[\\\"']");
    const auto lines = QString::fromUtf8(output).split('\n');
    for (const auto &line : lines)
        if (expression.match(line).hasMatch())
            return true;
    return false;
}

bool parseEnabled(const QByteArray &output, bool *enabled) {
    const QRegularExpression expression("^\\s*Status:\\s*(Enabled|Disabled)\\b",
                                        QRegularExpression::CaseInsensitiveOption |
                                            QRegularExpression::MultilineOption);
    const auto match = expression.match(QString::fromUtf8(output));
    if (!match.hasMatch())
        return false;
    *enabled = match.captured(1).compare("Enabled", Qt::CaseInsensitive) == 0;
    return true;
}

bool parseRules(const QByteArray &output, int *ruleCount, bool *hasTrafficCounters) {
    static const QRegularExpression rule("^\\s*@\\d+\\b");
    static const QRegularExpression counter(
        "Evaluations:\\s*(\\d+)\\s+Packets:\\s*(\\d+)\\s+Bytes:\\s*(\\d+)",
        QRegularExpression::CaseInsensitiveOption);
    *ruleCount = 0;
    *hasTrafficCounters = false;
    const auto lines = QString::fromUtf8(output).split('\n');
    for (const auto &line : lines) {
        if (line.trimmed().isEmpty())
            continue;
        if (rule.match(line).hasMatch()) {
            ++*ruleCount;
            continue;
        }
        const auto match = counter.match(line);
        if (match.hasMatch()) {
            bool packetsOk = false;
            bool bytesOk = false;
            const auto packets = match.captured(2).toULongLong(&packetsOk);
            const auto bytes = match.captured(3).toULongLong(&bytesOk);
            if (!packetsOk || !bytesOk)
                return false;
            *hasTrafficCounters = *hasTrafficCounters || packets > 0 || bytes > 0;
            continue;
        }
        // -sr/-sn output uses indexed rule lines plus optional verbose counter lines.
        if (line.trimmed().startsWith('[') && line.trimmed().endsWith(']'))
            continue;
        return false;
    }
    return true;
}

bool parseAnchorListing(const QByteArray &output, const QString &sessionId, bool *loaded) {
    static const QRegularExpression component("^[A-Za-z0-9_.-]+$|^\\*$");
    *loaded = false;
    const auto lines = QString::fromUtf8(output).split('\n');
    for (auto line : lines) {
        line = line.trimmed();
        if (line.isEmpty())
            continue;
        const auto parts = line.split('/');
        for (const auto &part : parts)
            if (!component.match(part).hasMatch())
                return false;
        if (line == sessionId || line == applicationAnchor + "/" + sessionId)
            *loaded = true;
    }
    return true;
}

bool parseRuleListing(const QByteArray &output) {
    int ignoredCount = 0;
    bool ignoredCounters = false;
    return parseRules(output, &ignoredCount, &ignoredCounters);
}

bool parseStateCandidates(const QByteArray &output, const SessionConfig &config, int *count) {
    *count = 0;
    const auto text = QString::fromUtf8(output);
    if (text.trimmed().isEmpty())
        return true;
    static const QRegularExpression row("^\\s*(?:all|inet|inet6)\\s+(?:tcp|udp)\\b",
                                        QRegularExpression::CaseInsensitiveOption);
    const QRegularExpression clientEndpoint(
        "(?<![0-9.])" + QRegularExpression::escape(config.clientIp) + ":[0-9]+(?![0-9])");
    const QRegularExpression serverEndpoint("(?<![0-9.])" +
                                            QRegularExpression::escape(config.serverIp) + ":" +
                                            QString::number(config.serverPort) + "(?![0-9])");
    const auto lines = text.split('\n');
    for (const auto &line : lines) {
        if (line.trimmed().isEmpty())
            continue;
        if (!row.match(line).hasMatch())
            return false;
        const auto arrowIndex = line.indexOf("->");
        if (arrowIndex < 0)
            return false;
        const auto sourceSide = line.left(arrowIndex);
        const auto destinationSide = line.mid(arrowIndex + 2);
        if (clientEndpoint.match(sourceSide).hasMatch() &&
            serverEndpoint.match(destinationSide).hasMatch())
            ++*count;
    }
    return true;
}

} // namespace

QJsonObject PfDiagnosticsResult::toSanitizedJson() const {
    QJsonArray errors;
    for (const auto &error : validationErrors)
        errors.append(error);
    QJsonArray queryResults;
    for (const auto &query : queries)
        queryResults.append(
            QJsonObject{{"query", queryName(query.query)}, {"status", query.status}});
    QJsonObject status;
    status.insert("known", pfEnabledKnown);
    if (pfEnabledKnown)
        status.insert("enabled", pfEnabled);
    QJsonObject filterAttachment;
    filterAttachment.insert("known", filterAttachmentKnown);
    if (filterAttachmentKnown)
        filterAttachment.insert("referenced_from_main", filterAttachmentReferenced);
    QJsonObject translationAttachment;
    translationAttachment.insert("known", translationAttachmentKnown);
    if (translationAttachmentKnown)
        translationAttachment.insert("referenced_from_main", translationAttachmentReferenced);
    QJsonObject anchor;
    anchor.insert("known", sessionAnchorKnown);
    if (sessionAnchorKnown)
        anchor.insert("loaded", sessionAnchorLoaded);
    QJsonObject rules;
    rules.insert("known", sessionRulesKnown);
    if (sessionRulesKnown) {
        rules.insert("filter_count", sessionFilterRuleCount);
        rules.insert("translation_count", sessionTranslationRuleCount);
    }
    QJsonObject counters;
    counters.insert("known", filterCountersKnown);
    if (filterCountersKnown)
        counters.insert("filter_traffic_counters_nonzero", filterCountersNonzero);
    QJsonObject states;
    states.insert("scope", "global_dump_filtered_in_memory");
    states.insert("known", stateCandidatesKnown);
    if (stateCandidatesKnown)
        states.insert("matching_candidate_count", stateCandidateCount);
    states.insert("output_recognized", stateOutputRecognized);
    states.insert("anchor_attribution", false);
    return {{"schema", "llm-interceptor.pf-diagnostics.v1"},
            {"sanitized", true},
            {"timeout_ms", timeoutMs},
            {"complete", complete},
            {"status", statusCode},
            {"pf", status},
            {"filter_attachment", filterAttachment},
            {"translation_attachment", translationAttachment},
            {"session_anchor", anchor},
            {"session_rules", rules},
            {"rule_counters", counters},
            {"state_candidates", states},
            {"evaluation_proven", evaluationProven},
            {"queries", queryResults},
            {"validation_errors", errors}};
}

PfDiagnosticsResult PfDiagnostics::collect(const SessionConfig &config, const QString &sessionId,
                                           PfCommandRunner &runner, int timeoutMs) {
    PfDiagnosticsResult result;
    result.timeoutMs = timeoutMs;
    result.validationErrors = config.validate();
    static const QRegularExpression sessionPattern("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$");
    if (!sessionPattern.match(sessionId).hasMatch())
        result.validationErrors << "Enter a valid session identifier.";
    if (timeoutMs < 1 || timeoutMs > maximumTimeoutMs)
        result.validationErrors << "PF query timeout must be between 1 and 5000 milliseconds.";
    if (!result.validationErrors.isEmpty()) {
        result.statusCode = "invalid_input";
        return result;
    }
    result.configValid = true;

    const QString anchor = applicationAnchor + "/" + sessionId;
    const QVector<PfQuery> order = {PfQuery::Status,
                                    PfQuery::MainFilterRules,
                                    PfQuery::MainTranslationRules,
                                    PfQuery::ApplicationAnchors,
                                    PfQuery::SessionFilterRules,
                                    PfQuery::SessionTranslationRules,
                                    PfQuery::States};
    for (qsizetype index = 0; index < order.size(); ++index) {
        const auto query = order[index];
        const auto output = runner.query(query, anchor, timeoutMs, maximumOutputBytes);
        if (output.status != PfCommandStatus::Completed || output.exitCode != 0) {
            const auto failure = output.status == PfCommandStatus::Completed
                                     ? QString("failed")
                                     : commandStatusName(output.status);
            result.queries.append({query, failure});
            for (qsizetype remaining = index + 1; remaining < order.size(); ++remaining)
                result.queries.append({order[remaining], "not_run"});
            result.statusCode = failure;
            return result;
        }

        bool parsed = true;
        switch (query) {
        case PfQuery::Status:
            result.pfEnabledKnown = parseEnabled(output.standardOutput, &result.pfEnabled);
            parsed = result.pfEnabledKnown;
            break;
        case PfQuery::MainFilterRules:
            parsed = parseRuleListing(output.standardOutput);
            if (!parsed)
                break;
            result.filterAttachmentReferenced =
                lineMentionsAttachment(output.standardOutput, "anchor", "llm_interceptor/*");
            result.filterAttachmentKnown = true;
            break;
        case PfQuery::MainTranslationRules:
            parsed = parseRuleListing(output.standardOutput);
            if (!parsed)
                break;
            result.translationAttachmentReferenced =
                lineMentionsAttachment(output.standardOutput, "rdr-anchor", "llm_interceptor/*");
            result.translationAttachmentKnown = true;
            break;
        case PfQuery::ApplicationAnchors:
            parsed =
                parseAnchorListing(output.standardOutput, sessionId, &result.sessionAnchorLoaded);
            if (!parsed)
                break;
            result.sessionAnchorKnown = true;
            break;
        case PfQuery::SessionFilterRules: {
            bool counters = false;
            parsed = parseRules(output.standardOutput, &result.sessionFilterRuleCount, &counters);
            if (parsed) {
                result.filterCountersNonzero = counters;
                result.filterCountersKnown = true;
            }
            break;
        }
        case PfQuery::SessionTranslationRules: {
            bool counters = false;
            parsed =
                parseRules(output.standardOutput, &result.sessionTranslationRuleCount, &counters);
            if (parsed)
                result.sessionRulesKnown = result.filterCountersKnown;
            break;
        }
        case PfQuery::States:
            result.stateCandidatesKnown =
                parseStateCandidates(output.standardOutput, config, &result.stateCandidateCount);
            result.stateOutputRecognized = result.stateCandidatesKnown;
            parsed = result.stateCandidatesKnown;
            break;
        }
        if (!parsed) {
            result.queries.append({query, "unrecognized_output"});
            for (qsizetype remaining = index + 1; remaining < order.size(); ++remaining)
                result.queries.append({order[remaining], "not_run"});
            result.statusCode = "unrecognized_output";
            return result;
        }
        result.queries.append({query, "completed"});
    }
    result.complete = result.sessionRulesKnown && result.stateCandidatesKnown;
    result.statusCode = result.complete ? "diagnostics_complete" : "incomplete";
    return result;
}

PfCommandRunner &systemPfCommandRunner() {
    static SystemPfCommandRunner runner;
    return runner;
}

} // namespace interceptor
