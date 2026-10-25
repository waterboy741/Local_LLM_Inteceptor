#pragma once

#include "PfAnchorRecoveryCoordinator.hpp"
#include "PfDiagnostics.hpp"

namespace interceptor {

class PfCommandAnchorCleanupVerifier final : public PfAnchorCleanupVerifier {
  public:
    static constexpr int defaultTimeoutMs = 3000;
    static constexpr qsizetype maximumOutputBytes = 64 * 1024;

    explicit PfCommandAnchorCleanupVerifier(PfCommandRunner &runner,
                                            int timeoutMs = defaultTimeoutMs)
        : runner_(runner), timeoutMs_(timeoutMs) {}

    PfAnchorCleanupVerification verifyOwnedAnchorEmpty(const SessionSnapshot &snapshot) override;

  private:
    PfCommandRunner &runner_;
    int timeoutMs_;
};

} // namespace interceptor
