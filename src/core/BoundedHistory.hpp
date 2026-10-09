#pragma once
#include <QString>
#include <QtGlobal>
#include <deque>
#include <mutex>
#include <stdexcept>
#include <vector>
namespace interceptor {
struct RequestEvent {
    quint64 id;
    QString summary;
};
class BoundedHistory {
  public:
    explicit BoundedHistory(std::size_t capacity) : capacity_(capacity) {
        if (capacity == 0)
            throw std::invalid_argument("History capacity must be positive");
    }
    void append(RequestEvent event) {
        // Bound metadata as well as row count. Full bodies belong to a separately bounded pipeline.
        event.summary = event.summary.left(4096);
        const std::lock_guard lock(mutex_);
        if (events_.size() == capacity_)
            events_.pop_front();
        events_.push_back(std::move(event));
    }
    std::vector<RequestEvent> snapshot() const {
        const std::lock_guard lock(mutex_);
        return {events_.begin(), events_.end()};
    }
    std::size_t size() const {
        const std::lock_guard lock(mutex_);
        return events_.size();
    }
    void clear() {
        const std::lock_guard lock(mutex_);
        events_.clear();
    }

  private:
    const std::size_t capacity_;
    mutable std::mutex mutex_;
    std::deque<RequestEvent> events_;
};
} // namespace interceptor
