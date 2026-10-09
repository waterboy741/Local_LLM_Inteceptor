#include "MockOllama.hpp"
#include "proxy/ProxyServer.hpp"

#include <QJsonDocument>
#include <QJsonObject>
#include <QtTest>

using namespace interceptor;

class M3ModificationTests : public QObject {
    Q_OBJECT

  private:
    static SessionConfig configFor(const MockOllama &mock) {
        return {"synthetic0",
                "192.0.2.10",
                "127.0.0.1",
                int(mock.serverPort()),
                {"/api/generate", "/api/chat"}};
    }
    static QByteArray request(const QByteArray &body, const QByteArray &path = "/api/generate") {
        return "POST " + path +
               " HTTP/1.1\r\nHost: synthetic\r\nContent-Type: "
               "application/json\r\nContent-Length: " +
               QByteArray::number(body.size()) + "\r\n\r\n" + body;
    }
    static void connectClient(QTcpSocket &client, ProxyServer &proxy) {
        client.connectToHost(QHostAddress::LocalHost, proxy.listenPort());
    }
    static ModificationOptions holding() {
        ModificationOptions options;
        options.mode = InterceptionMode::Modify;
        options.holdMatching = true;
        return options;
    }
    static JsonRule promptRule(const QString &id, const QString &replacement) {
        return {id, "/api/generate", "", {"prompt"}, replacement};
    }

  private slots:
    void observeNeverModifiesEvenWithRules() {
        MockOllama mock;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        ModificationOptions options;
        options.rules = {promptRule("observe-rule", "changed")};
        QVERIFY(proxy.setModificationOptions(options));
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        const QByteArray body = " { \"model\": \"fixture\", \"prompt\": \"original\" } ";
        client.write(request(body));
        QTRY_COMPARE(mock.bodies.size(), 1);
        QCOMPARE(mock.bodies.front(), body);
        QTRY_COMPARE(proxy.history().size(), std::size_t(1));
        QVERIFY(!proxy.history().front().modified);
        QVERIFY(proxy.held().empty());
    }

    void orderedNestedRulesPreserveUnicodeAndUnknownFields() {
        MockOllama mock;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        ModificationOptions options;
        options.mode = InterceptionMode::Modify;
        options.rules = {
            promptRule("first", "first edit"),
            promptRule("second", QString::fromUtf8("こんにちは 🤖")),
            {"temperature", "/api/generate", "fixture", {"options", "temperature"}, 0.2},
            {"wrong-model", "/api/generate", "other", {"model"}, "should-not-apply"}};
        QVERIFY(proxy.setModificationOptions(options));
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        const QByteArray original =
            QString::fromUtf8(
                "{\"model\":\"fixture\",\"prompt\":\"original\",\"options\":{\"temperature\":0.9,"
                "\"unknown\":\"café\"},\"extra\":{\"keep\":true}}")
                .toUtf8();
        auto expected = QJsonDocument::fromJson(original).object();
        expected["prompt"] = QString::fromUtf8("こんにちは 🤖");
        auto nested = expected["options"].toObject();
        nested["temperature"] = 0.2;
        expected["options"] = nested;
        client.write(request(original));
        QTRY_COMPARE(mock.bodies.size(), 1);
        QCOMPARE(QJsonDocument::fromJson(mock.bodies.front()).object(), expected);
        QTRY_COMPARE(proxy.history().size(), std::size_t(1));
        const auto record = proxy.history().front();
        QVERIFY(record.modified);
        QCOMPARE(record.originalBody, original);
        QCOMPARE(record.modifiedBody, mock.bodies.front());
        QCOMPARE(record.audit.count("rule: first"), 1);
        QCOMPARE(record.audit.count("rule: second"), 1);
        QCOMPARE(record.audit.count("rule: temperature"), 1);
        QVERIFY(record.audit.indexOf("rule: first") < record.audit.indexOf("rule: second"));
        QVERIFY(!record.audit.contains("rule: wrong-model"));
    }

    void unmatchedPathsAndMissingFieldsRemainByteIdentical() {
        MockOllama mock;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        ModificationOptions options;
        options.mode = InterceptionMode::Modify;
        options.rules = {{"missing", "/api/generate", "", {"options", "missing"}, true}};
        QVERIFY(proxy.setModificationOptions(options));
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        const QByteArray original = " { \"model\": \"fixture\", \"prompt\": \"keep bytes\" } ";
        client.write(request(original));
        QTRY_COMPARE(mock.bodies.size(), 1);
        QCOMPARE(mock.bodies.front(), original);
        client.write(request(original, "/other"));
        QTRY_COMPARE(mock.bodies.size(), 2);
        QCOMPARE(mock.bodies.back(), original);
        QVERIFY(proxy.held().empty());
    }

    void manualValidationAndExactEditedBytes() {
        MockOllama mock;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        auto options = holding();
        options.maxEditableBytes = 128;
        QVERIFY(proxy.setModificationOptions(options));
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        const QByteArray original = "{\"model\":\"fixture\",\"prompt\":\"short\"}";
        client.write(request(original));
        QTRY_COMPARE(proxy.held().size(), std::size_t(1));
        const auto held = proxy.held().front();
        QCOMPARE(held.originalBody, original);
        QVERIFY(held.remainingMs > 0);
        QCOMPARE(mock.bodies.size(), 0);
        QVERIFY(!proxy.resolveHeld(held.id, "{"));
        QVERIFY(!proxy.resolveHeld(held.id, "{\"model\":12,\"prompt\":\"bad\"}"));
        QVERIFY(!proxy.resolveHeld(held.id, "{\"model\":\"fixture\",\"prompt\":\"" +
                                                QByteArray(256, 'x') + "\"}"));
        QCOMPARE(proxy.held().size(), std::size_t(1));
        QCOMPARE(mock.bodies.size(), 0);
        const QByteArray edited = QString::fromUtf8(" { \"model\": \"fixture\", \"prompt\": "
                                                    "\"longer café 🤖 text\", \"unknown\": true } ")
                                      .toUtf8();
        QVERIFY(proxy.resolveHeld(held.id, edited));
        QVERIFY(!proxy.resolveHeld(held.id, edited));
        QTRY_COMPARE(mock.bodies.size(), 1);
        QCOMPARE(mock.bodies.front(), edited);
        QTRY_COMPARE(proxy.history().size(), std::size_t(1));
        QCOMPARE(proxy.history().front().originalBody, original);
        QCOMPARE(proxy.history().front().modifiedBody, edited);
        QVERIFY(proxy.history().front().modified);
        QVERIFY(!proxy.history().front().audit.isEmpty());
    }

    void concurrentHoldsCapacityAndOutOfOrderRelease() {
        MockOllama mock;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        auto options = holding();
        options.maxHeld = 2;
        QVERIFY(proxy.setModificationOptions(options));
        QTcpSocket first, second, third;
        for (auto *client : {&first, &second, &third}) {
            connectClient(*client, proxy);
            QTRY_COMPARE(client->state(), QAbstractSocket::ConnectedState);
        }
        const QByteArray one = "{\"model\":\"fixture\",\"prompt\":\"one\"}";
        const QByteArray two = "{\"model\":\"fixture\",\"prompt\":\"two\"}";
        first.write(request(one));
        QTRY_COMPARE(proxy.held().size(), std::size_t(1));
        const auto firstId = proxy.held().front().id;
        second.write(request(two));
        QTRY_COMPARE(proxy.held().size(), std::size_t(2));
        const auto secondId = proxy.held().back().id;
        QVERIFY(firstId != secondId);
        auto changed = options;
        changed.rules = {promptRule("too-late", "must not replace held decisions")};
        QVERIFY(!proxy.setModificationOptions(changed));
        QCOMPARE(proxy.held().size(), std::size_t(2));
        third.write(request(one));
        QTRY_VERIFY(third.bytesAvailable() > 0);
        QVERIFY(third.readAll().startsWith("HTTP/1.1 503"));
        QCOMPARE(mock.bodies.size(), 0);
        QVERIFY(proxy.resolveHeld(secondId, {}, true));
        QTRY_COMPARE(mock.bodies.size(), 1);
        QCOMPARE(mock.bodies.front(), two);
        QVERIFY(proxy.resolveHeld(firstId, {}, true));
        QTRY_COMPARE(mock.bodies.size(), 2);
        QCOMPARE(mock.bodies.back(), one);
        QVERIFY(proxy.held().empty());
    }

    void deadlineAndObserveSwitchReleaseOriginals() {
        MockOllama mock;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        auto options = holding();
        options.holdTimeoutMs = 200;
        options.rules = {promptRule("proposed", "must not forward on timeout")};
        QVERIFY(proxy.setModificationOptions(options));
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        const QByteArray original = " {\"model\":\"fixture\",\"prompt\":\"original\"} ";
        client.write(request(original));
        QTRY_COMPARE(proxy.held().size(), std::size_t(1));
        QVERIFY(proxy.held().front().proposedBody != original);
        QTRY_COMPARE(mock.bodies.size(), 1);
        QCOMPARE(mock.bodies.front(), original);
        QVERIFY(proxy.held().empty());
        options.holdTimeoutMs = 30000;
        QVERIFY(proxy.setModificationOptions(options));
        client.write(request(original));
        QTRY_COMPARE(proxy.held().size(), std::size_t(1));
        options.mode = InterceptionMode::Observe;
        QVERIFY(proxy.setModificationOptions(options));
        QTRY_COMPARE(mock.bodies.size(), 2);
        QCOMPARE(mock.bodies.back(), original);
        QVERIFY(proxy.held().empty());
    }

    void disconnectAndStopCancelWithoutUpstream() {
        MockOllama mock;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        QVERIFY(proxy.setModificationOptions(holding()));
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        const QByteArray original = "{\"model\":\"fixture\",\"prompt\":\"never send\"}";
        client.write(request(original));
        QTRY_COMPARE(proxy.held().size(), std::size_t(1));
        const auto cancelledId = proxy.held().front().id;
        client.abort();
        QTRY_VERIFY(proxy.held().empty());
        QVERIFY(!proxy.resolveHeld(cancelledId, {}, true));
        QTcpSocket pending;
        connectClient(pending, proxy);
        QTRY_COMPARE(pending.state(), QAbstractSocket::ConnectedState);
        pending.write(request(original));
        QTRY_COMPARE(proxy.held().size(), std::size_t(1));
        proxy.stop();
        QTRY_COMPARE(pending.state(), QAbstractSocket::UnconnectedState);
        QCOMPARE(mock.bodies.size(), 0);
    }

    void oversizedOrInvalidIncomingBodiesAreNeverEdited() {
        MockOllama mock;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        auto options = holding();
        options.maxEditableBytes = 32;
        options.rules = {promptRule("skip", "modified")};
        QVERIFY(proxy.setModificationOptions(options));
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        const QByteArray oversized = " {\"model\":\"fixture\",\"prompt\":\"too large to edit\"} ";
        client.write(request(oversized));
        QTRY_COMPARE(mock.bodies.size(), 1);
        QCOMPARE(mock.bodies.front(), oversized);
        QVERIFY(proxy.held().empty());
        client.write(request("{invalid}"));
        QTRY_COMPARE(mock.bodies.size(), 2);
        QCOMPARE(mock.bodies.back(), QByteArray("{invalid}"));
        QVERIFY(proxy.held().empty());
    }

    void chatEditValidatesMessageShapeAndPreservesExactUnicodeBytes() {
        MockOllama mock;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        QVERIFY(proxy.setModificationOptions(holding()));
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        const QByteArray original =
            "{\"model\":\"fixture\",\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}]}";
        client.write(request(original, "/api/chat"));
        QTRY_COMPARE(proxy.held().size(), std::size_t(1));
        const auto id = proxy.held().front().id;
        for (const auto &invalid :
             {QByteArray("{\"model\":\"fixture\",\"messages\":12}"),
              QByteArray(
                  "{\"model\":\"fixture\",\"messages\":[{\"role\":\"user\",\"content\":12}]}"),
              QByteArray("{\"model\":\"fixture\",\"messages\":[{\"role\":\"unknown\",\"content\":"
                         "\"text\"}]}")}) {
            QVERIFY(!proxy.resolveHeld(id, invalid));
            QCOMPARE(mock.bodies.size(), 0);
            QCOMPARE(proxy.held().size(), std::size_t(1));
        }
        const auto edited =
            QString::fromUtf8(
                " { \"model\":\"fixture\", \"messages\":[{\"role\":\"user\",\"content\":\"café "
                "🤖\"}], \"custom\":true } ")
                .toUtf8();
        QVERIFY(proxy.resolveHeld(id, edited));
        QTRY_COMPARE(mock.bodies.size(), 1);
        QCOMPARE(mock.bodies.front(), edited);
    }

    void forwardingOriginalDoesNotClaimProposedRulesWereApplied() {
        MockOllama mock;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        auto options = holding();
        options.rules = {promptRule("proposal-only", "changed")};
        QVERIFY(proxy.setModificationOptions(options));
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        const QByteArray original = " {\"model\":\"fixture\",\"prompt\":\"original\"} ";
        client.write(request(original));
        QTRY_COMPARE(proxy.held().size(), std::size_t(1));
        const auto pending = proxy.held().front();
        QVERIFY(pending.proposedBody != original);
        QVERIFY(proxy.resolveHeld(pending.id, {}, true));
        QTRY_COMPARE(mock.bodies.size(), 1);
        QCOMPARE(mock.bodies.front(), original);
        QTRY_COMPARE(proxy.history().size(), std::size_t(1));
        const auto event = proxy.history().front();
        QVERIFY(!event.modified);
        QVERIFY(!event.audit.contains("rule: proposal-only"));
        QVERIFY(event.audit.contains("manual: original"));
    }

    void unsupportedHeadersNeverEnterHoldQueue() {
        MockOllama mock;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        QVERIFY(proxy.setModificationOptions(holding()));
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        auto wire = request("{\"model\":\"fixture\",\"prompt\":\"no hold\"}");
        wire.replace("Host:", "X-Unknown: one\r\nX-Unknown: two\r\nHost:");
        client.write(wire);
        QTRY_VERIFY(client.bytesAvailable() > 0);
        QVERIFY(client.readAll().startsWith("HTTP/1.1 400"));
        QVERIFY(proxy.held().empty());
        QCOMPARE(mock.bodies.size(), 0);
    }

    void oldSessionHoldIdsCannotReleaseNewRequests() {
        MockOllama mock;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        QVERIFY(proxy.setModificationOptions(holding()));
        QTcpSocket first;
        connectClient(first, proxy);
        QTRY_COMPARE(first.state(), QAbstractSocket::ConnectedState);
        const QByteArray original = "{\"model\":\"fixture\",\"prompt\":\"old session\"}";
        first.write(request(original));
        QTRY_COMPARE(proxy.held().size(), std::size_t(1));
        const auto oldId = proxy.held().front().id;
        proxy.stop();
        QTRY_COMPARE(first.state(), QAbstractSocket::UnconnectedState);
        QVERIFY(proxy.start(configFor(mock)));
        QVERIFY(proxy.setModificationOptions(holding()));
        QTcpSocket second;
        connectClient(second, proxy);
        QTRY_COMPARE(second.state(), QAbstractSocket::ConnectedState);
        second.write(request(original));
        QTRY_COMPARE(proxy.held().size(), std::size_t(1));
        const auto newId = proxy.held().front().id;
        QVERIFY(newId != oldId);
        QVERIFY(!proxy.resolveHeld(oldId, {}, true));
        QCOMPARE(proxy.held().size(), std::size_t(1));
        QCOMPARE(mock.bodies.size(), 0);
        QVERIFY(proxy.resolveHeld(newId, {}, true));
        QTRY_COMPARE(mock.bodies.size(), 1);
        QCOMPARE(mock.bodies.front(), original);
    }

    void integrityProtectedBodiesAreForwardedWithoutEditsOrHolds() {
        MockOllama mock;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        auto options = holding();
        options.rules = {promptRule("never-apply", "changed")};
        QVERIFY(proxy.setModificationOptions(options));
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        const QByteArray original = " {\"model\":\"fixture\",\"prompt\":\"signed body\"} ";
        auto wire = request(original);
        wire.replace("Host:", "Signature-Input: synthetic-fixture\r\nHost:");
        client.write(wire);
        QTRY_COMPARE(mock.bodies.size(), 1);
        QCOMPARE(mock.bodies.front(), original);
        QVERIFY(proxy.held().empty());
        QTRY_COMPARE(proxy.history().size(), std::size_t(1));
        QVERIFY(!proxy.history().front().modified);
        QVERIFY(!proxy.history().front().audit.contains("rule: never-apply"));
    }

    void invalidRuleGeneratedSchemaFallsBackToOriginal() {
        MockOllama mock;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        ModificationOptions options;
        options.mode = InterceptionMode::Modify;
        options.rules = {{"bad-model", "/api/generate", "", {"model"}, 12}};
        QVERIFY(proxy.setModificationOptions(options));
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        const QByteArray original = " {\"model\":\"fixture\",\"prompt\":\"keep\"} ";
        client.write(request(original));
        QTRY_COMPARE(mock.bodies.size(), 1);
        QCOMPARE(mock.bodies.front(), original);
        QTRY_COMPARE(proxy.history().size(), std::size_t(1));
        QVERIFY(!proxy.history().front().modified);
        QVERIFY(proxy.history().front().audit.contains("rules invalid: original"));
    }

    void modificationLimitsAndDuplicateRuleIdsAreValidated() {
        ProxyServer proxy;
        auto options = holding();
        QVERIFY(proxy.setModificationOptions(options));
        for (const std::size_t limit : {std::size_t(0), std::size_t(9)}) {
            auto invalid = options;
            invalid.maxHeld = limit;
            QVERIFY(!proxy.setModificationOptions(invalid));
        }
        for (const std::size_t limit : {std::size_t(0), std::size_t(1048577)}) {
            auto invalid = options;
            invalid.maxEditableBytes = limit;
            QVERIFY(!proxy.setModificationOptions(invalid));
        }
        for (const int limit : {0, -1, 300001}) {
            auto invalid = options;
            invalid.holdTimeoutMs = limit;
            QVERIFY(!proxy.setModificationOptions(invalid));
        }
        auto invalid = options;
        invalid.rules = {promptRule("same-id", "one"), promptRule("same-id", "two")};
        QVERIFY(!proxy.setModificationOptions(invalid));
        invalid = options;
        for (int index = 0; index < 33; ++index)
            invalid.rules.push_back(promptRule(QString::number(index), "bounded"));
        QVERIFY(!proxy.setModificationOptions(invalid));
        QVERIFY(proxy.setModificationOptions(options));
    }

    void deepIncomingJsonIsRelayedWithoutEditing() {
        MockOllama mock;
        ProxyServer proxy;
        QVERIFY(proxy.start(configFor(mock)));
        auto options = holding();
        options.rules = {promptRule("skip-depth", "changed")};
        QVERIFY(proxy.setModificationOptions(options));
        QTcpSocket client;
        connectClient(client, proxy);
        QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
        QByteArray nested = "true";
        for (int index = 0; index < 40; ++index)
            nested = "{\"child\":" + nested + "}";
        const QByteArray original =
            "{\"model\":\"fixture\",\"prompt\":\"unchanged\",\"nested\":" + nested + "}";
        client.write(request(original));
        QTRY_COMPARE(mock.bodies.size(), 1);
        QCOMPARE(mock.bodies.front(), original);
        QVERIFY(proxy.held().empty());
    }

    void dispatchedEditsRetainAuditOnUpstreamFailure() {
        for (const bool timeout : {false, true}) {
            MockOllama mock;
            const auto config = configFor(mock);
            mock.stall = timeout;
            if (!timeout)
                mock.close();
            ProxyOptions transport;
            transport.timeoutMs = 150;
            ProxyServer proxy;
            QVERIFY(proxy.start(config, transport));
            auto modification = holding();
            modification.holdMatching = !timeout;
            modification.rules = {promptRule("failed-rule", "rule failure")};
            QVERIFY(proxy.setModificationOptions(modification));
            QTcpSocket client;
            connectClient(client, proxy);
            QTRY_COMPARE(client.state(), QAbstractSocket::ConnectedState);
            const QByteArray original = " {\"model\":\"fixture\",\"prompt\":\"original\"} ";
            QByteArray expected;
            client.write(request(original));
            if (!timeout) {
                QTRY_COMPARE(proxy.held().size(), std::size_t(1));
                expected = " {\"model\":\"fixture\",\"prompt\":\"manual failure\"} ";
                QVERIFY(proxy.resolveHeld(proxy.held().front().id, expected));
            } else {
                auto object = QJsonDocument::fromJson(original).object();
                object["prompt"] = "rule failure";
                expected = QJsonDocument(object).toJson(QJsonDocument::Compact);
            }
            QTRY_VERIFY(client.bytesAvailable() > 0);
            const int status = timeout ? 504 : 502;
            QVERIFY(client.readAll().startsWith("HTTP/1.1 " + QByteArray::number(status)));
            QTRY_COMPARE(proxy.history().size(), std::size_t(1));
            const auto event = proxy.history().front();
            QCOMPARE(event.status, status);
            QCOMPARE(event.originalBody, original);
            QCOMPARE(event.modifiedBody, expected);
            QVERIFY(event.modified);
            QVERIFY(event.audit.contains(timeout ? "rule: failed-rule" : "manual: edited"));
            QCOMPARE(mock.bodies.size(), timeout ? 1 : 0);
        }
    }
};

QTEST_GUILESS_MAIN(M3ModificationTests)
#include "M3ModificationTests.moc"
