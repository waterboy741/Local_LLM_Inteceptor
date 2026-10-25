#pragma once

#include "core/SessionConfig.hpp"

#include <QByteArray>
#include <QJsonObject>
#include <QString>
#include <QStringList>
#include <QVector>
#include <optional>

namespace interceptor {

enum class PfQuery {
    Status,
    MainFilterRules,
    MainTranslationRules,
    ApplicationAnchors,
    SessionFilterRules,
    SessionTranslationRules,
    States
};

enum class PfCommandStatus { Completed, PermissionDenied, TimedOut, OutputLimitExceeded, Failed };

struct PfQueryOutput {
    PfCommandStatus status = PfCommandStatus::Failed;
    int exitCode = -1;
    QByteArray standardOutput;
};

class PfCommandRunner {
  public:
    virtual ~PfCommandRunner() = default;
    virtual PfQueryOutput query(PfQuery query, const QString &sessionAnchor, int timeoutMs,
                                qsizetype outputLimitBytes) = 0;
};

struct PfQueryDiagnostic {
    PfQuery query;
    QString status;
};

struct PfDiagnosticsResult {
    bool configValid = false;
    bool complete = false;
    bool pfEnabledKnown = false;
    bool pfEnabled = false;
    bool filterAttachmentKnown = false;
    bool filterAttachmentReferenced = false;
    bool translationAttachmentKnown = false;
    bool translationAttachmentReferenced = false;
    bool sessionAnchorKnown = false;
    bool sessionAnchorLoaded = false;
    bool sessionRulesKnown = false;
    int sessionFilterRuleCount = 0;
    int sessionTranslationRuleCount = 0;
    bool filterCountersKnown = false;
    bool filterCountersNonzero = false;
    bool stateCandidatesKnown = false;
    int stateCandidateCount = 0;
    bool stateOutputRecognized = false;
    bool evaluationProven = false;
    int timeoutMs = 0;
    QString statusCode;
    QStringList validationErrors;
    QVector<PfQueryDiagnostic> queries;

    QJsonObject toSanitizedJson() const;
};

struct PfPreInstallReadinessResult {
    bool ready = false;
    bool pfEnabledKnown = false;
    bool pfEnabled = false;
    bool filterAttachmentKnown = false;
    bool filterAttachmentReferenced = false;
    bool translationAttachmentKnown = false;
    bool translationAttachmentReferenced = false;
    int timeoutMs = 0;
    QString statusCode;
    QVector<PfQueryDiagnostic> queries;

    QJsonObject toSanitizedJson() const;
};

class PfDiagnostics {
  public:
    static constexpr int defaultTimeoutMs = 3000;
    static constexpr int maximumTimeoutMs = 5000;
    static constexpr qsizetype maximumOutputBytes = 256 * 1024;

    static PfDiagnosticsResult collect(const SessionConfig &config, const QString &sessionId,
                                       PfCommandRunner &runner, int timeoutMs = defaultTimeoutMs);
    static PfPreInstallReadinessResult collectPreInstallReadiness(PfCommandRunner &runner,
                                                                  int timeoutMs = defaultTimeoutMs);
};

PfCommandRunner &systemPfCommandRunner();

} // namespace interceptor
