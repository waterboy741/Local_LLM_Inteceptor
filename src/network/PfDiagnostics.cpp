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
        if (!process.waitForStarted(timeoutMs)) {
            const bool startupTimedOut = timer.elapsed() >= timeoutMs;
            if (process.state() != QProcess::NotRunning) {
                process.kill();
                if (!process.waitForFinished(1000) && process.state() != QProcess::NotRunning)
                    result.status = PfCommandStatus::TimedOut;
            }
            if (startupTimedOut)
                result.status = PfCommandStatus::TimedOut;
            return result;
        }

        QByteArray permissionText;
        qsizetype observedBytes = 0;
        bool overflow = false;
        bool timedOut = false;
        auto drain = [&]() {
            const auto remaining = outputLimitBytes - observedBytes;
            const auto stdoutChunk = process.read(remaining + 1);
            if (stdoutChunk.size() > remaining) {
                overflow = true;
                process.kill();
                return;
            }
            process.setReadChannel(QProcess::StandardError);
            const auto stderrChunk = process.read(remaining - stdoutChunk.size() + 1);
            process.setReadChannel(QProcess::StandardOutput);
            const auto newlyObserved = stdoutChunk.size() + stderrChunk.size();
            observedBytes += newlyObserved;
            if (permissionText.size() < 4096)
                permissionText += stderrChunk.left(4096 - permissionText.size());
            if (newlyObserved > remaining) {
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
        if (!overflow && process.state() != QProcess::NotRunning)
            process.waitForFinished(100);
        if (!overflow)
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
    if (QString::fromUtf8(output).toUtf8() != output)
        return false;
    const QRegularExpression expression(
        "^\\s*Status:\\s*(Enabled|Disabled)(?:\\s+for\\s+\\d+\\s+days?\\s+"
        "\\d{2}:\\d{2}:\\d{2})?\\s*$",
        QRegularExpression::CaseInsensitiveOption | QRegularExpression::MultilineOption);
    const auto text = QString::fromUtf8(output);
    auto matches = expression.globalMatch(text);
    if (!matches.hasNext())
        return false;
    const auto match = matches.next();
    if (matches.hasNext())
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

bool validUtf8(const QByteArray &output) { return QString::fromUtf8(output).toUtf8() == output; }

bool parseMainAttachmentRules(const QByteArray &output, const QByteArray &expectedKind,
                              bool *referenced) {
    *referenced = false;
    if (!validUtf8(output) || !parseRuleListing(output))
        return false;

    static const QRegularExpression anchorDirective(
        "^\\s*@\\d+\\s+(?:anchor|rdr-anchor|nat-anchor|binat-anchor|scrub-anchor)\\b",
        QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression wellFormedDirective(
        "^\\s*@\\d+\\s+(?:anchor|rdr-anchor|nat-anchor|binat-anchor|scrub-anchor)\\s+"
        "([\\\"'])[^\\\"'\\r\\n]+\\1(?:\\s+.*)?$",
        QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression indexedRule("^\\s*@\\d+\\s+(\\S+)");
    static const QSet<QString> knownRuleKinds = {
        "pass",       "block",        "match", "anchor",       "rdr-anchor",
        "nat-anchor", "binat-anchor", "scrub", "scrub-anchor", "antispoof"};
    static const QRegularExpression verboseCounter(
        "^\\s*Evaluations:\\s*\\d+\\s+Packets:\\s*\\d+\\s+Bytes:\\s*\\d+\\s*$",
        QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression bracketedVerboseCounter(
        "^\\s*\\[\\s*Evaluations:\\s*\\d+\\s+Packets:\\s*\\d+\\s+Bytes:\\s*\\d+"
        "\\s*\\]\\s*$",
        QRegularExpression::CaseInsensitiveOption);
    const QString target = QString::fromLatin1(expectedKind) + "\\s+([\\\"'])" +
                           QRegularExpression::escape(QStringLiteral("llm_interceptor/*")) +
                           "\\1(?=\\s|$)";
    const QRegularExpression expectedReference("^\\s*@\\d+\\s+" + target,
                                               QRegularExpression::CaseInsensitiveOption);

    const auto lines = QString::fromUtf8(output).split('\n');
    int matchingReferences = 0;
    for (const auto &line : lines) {
        const auto trimmed = line.trimmed();
        if (trimmed.isEmpty())
            continue;
        if (verboseCounter.match(line).hasMatch() || bracketedVerboseCounter.match(line).hasMatch())
            continue;
        const auto ruleMatch = indexedRule.match(line);
        if (!ruleMatch.hasMatch() || !knownRuleKinds.contains(ruleMatch.captured(1).toLower()))
            return false;
        if (anchorDirective.match(line).hasMatch() && !wellFormedDirective.match(line).hasMatch())
            return false;
        if (expectedReference.match(line).hasMatch())
            ++matchingReferences;
    }
    if (matchingReferences > 1)
        return false;
    *referenced = matchingReferences == 1;
    return true;
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

QJsonObject PfPreInstallReadinessResult::toSanitizedJson() const {
    QJsonArray queryResults;
    for (const auto &query : queries)
        queryResults.append(
            QJsonObject{{"query", queryName(query.query)}, {"status", query.status}});

    QJsonObject pf;
    pf.insert("known", pfEnabledKnown);
    if (pfEnabledKnown)
        pf.insert("enabled", pfEnabled);
    QJsonObject filterAttachment;
    filterAttachment.insert("known", filterAttachmentKnown);
    if (filterAttachmentKnown)
        filterAttachment.insert("referenced_from_main", filterAttachmentReferenced);
    QJsonObject translationAttachment;
    translationAttachment.insert("known", translationAttachmentKnown);
    if (translationAttachmentKnown)
        translationAttachment.insert("referenced_from_main", translationAttachmentReferenced);

    return {{"schema", "llm-interceptor.pf-preinstall-readiness.v1"},
            {"sanitized", true},
            {"timeout_ms", timeoutMs},
            {"ready", ready},
            {"status", statusCode},
            {"pf", pf},
            {"filter_attachment", filterAttachment},
            {"translation_attachment", translationAttachment},
            {"references_observed_only", true},
            {"packet_evaluation_proven", false},
            {"queries", queryResults}};
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

PfPreInstallReadinessResult PfDiagnostics::collectPreInstallReadiness(PfCommandRunner &runner,
                                                                      int timeoutMs) {
    PfPreInstallReadinessResult result;
    result.timeoutMs = timeoutMs;
    if (timeoutMs < 1 || timeoutMs > maximumTimeoutMs) {
        result.statusCode = "invalid_timeout";
        return result;
    }

    const QVector<PfQuery> order = {PfQuery::Status, PfQuery::MainFilterRules,
                                    PfQuery::MainTranslationRules};
    for (const auto query : order) {
        const auto output = runner.query(query, {}, timeoutMs, maximumOutputBytes);
        if (output.status != PfCommandStatus::Completed || output.exitCode != 0 ||
            output.standardOutput.size() > maximumOutputBytes) {
            QString failure;
            if (output.status == PfCommandStatus::Completed) {
                failure = output.standardOutput.size() > maximumOutputBytes
                              ? "output_limit_exceeded"
                              : "failed";
            } else {
                failure = commandStatusName(output.status);
            }
            result.queries.append({query, failure});
            result.statusCode = failure;
            return result;
        }

        bool parsed = false;
        switch (query) {
        case PfQuery::Status:
            result.pfEnabledKnown = parseEnabled(output.standardOutput, &result.pfEnabled);
            parsed = result.pfEnabledKnown;
            break;
        case PfQuery::MainFilterRules:
            parsed = parseMainAttachmentRules(output.standardOutput, "anchor",
                                              &result.filterAttachmentReferenced);
            result.filterAttachmentKnown = parsed;
            break;
        case PfQuery::MainTranslationRules:
            parsed = parseMainAttachmentRules(output.standardOutput, "rdr-anchor",
                                              &result.translationAttachmentReferenced);
            result.translationAttachmentKnown = parsed;
            break;
        case PfQuery::ApplicationAnchors:
        case PfQuery::SessionFilterRules:
        case PfQuery::SessionTranslationRules:
        case PfQuery::States:
            break;
        }
        if (!parsed) {
            result.queries.append({query, "unrecognized_output"});
            result.statusCode = "unrecognized_output";
            return result;
        }
        result.queries.append({query, "completed"});

        if (query == PfQuery::Status && !result.pfEnabled) {
            result.statusCode = "pf_disabled";
            return result;
        }
        if (query == PfQuery::MainFilterRules && !result.filterAttachmentReferenced) {
            result.statusCode = "filter_attachment_missing";
            return result;
        }
        if (query == PfQuery::MainTranslationRules && !result.translationAttachmentReferenced) {
            result.statusCode = "translation_attachment_missing";
            return result;
        }
    }

    result.ready = true;
    result.statusCode = "preinstall_ready";
    return result;
}

PfCommandRunner &systemPfCommandRunner() {
    static SystemPfCommandRunner runner;
    return runner;
}

} // namespace interceptor
