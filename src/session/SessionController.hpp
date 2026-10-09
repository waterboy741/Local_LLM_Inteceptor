#pragma once
#include "core/SessionConfig.hpp"
#include <QObject>
#include <optional>
namespace interceptor {
class SessionController : public QObject {
    Q_OBJECT
  public:
    enum class State { Idle, Ready, Stopping };
    Q_ENUM(State)
    explicit SessionController(QObject *parent = nullptr);
    bool prepare(const SessionConfig &config);
    void stop();
    State state() const { return state_; }
    std::optional<SessionConfig> config() const { return config_; }
  signals:
    void stateChanged(interceptor::SessionController::State state);

  private:
    void setState(State state);
    State state_ = State::Idle;
    std::optional<SessionConfig> config_;
};
} // namespace interceptor
