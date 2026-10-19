#pragma once

#include "proxy/ProxyServer.hpp"
#include <QIODevice>
#include <map>
#include <vector>

namespace interceptor {

struct InspectionSummary {
    std::size_t count = 0;
    std::size_t modifiedCount = 0;
    std::size_t totalBodyBytes = 0;
    std::map<int, std::size_t> statusCounts;
};

InspectionSummary summarizeRequests(const std::vector<ObservedRequest> &requests);

// JSON Lines archive format. Sensitive object fields are recursively redacted by default.
bool exportRequests(QIODevice &device, const std::vector<ObservedRequest> &requests,
                    QString *error = nullptr, std::size_t maxRecords = 1000,
                    std::size_t maxTotalBytes = 16 * 1024 * 1024);
bool importRequests(QIODevice &device, std::vector<ObservedRequest> &requests,
                    QString *error = nullptr, std::size_t maxRecords = 1000,
                    std::size_t maxTotalBytes = 16 * 1024 * 1024);

} // namespace interceptor
