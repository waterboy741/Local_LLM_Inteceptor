"""Offline fixture integrity checks, not tests of a transport implementation."""

import json
import ipaddress
from pathlib import Path
import unittest


FIXTURES = Path(__file__).parent / "fixtures" / "m0"


def request_fixture(name):
    raw = (FIXTURES / (name + ".http")).read_bytes()
    head, body = raw.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    headers = dict(line.split(b": ", 1) for line in lines[1:])
    return lines[0], headers, body


class M0FixtureTests(unittest.TestCase):
    def test_chat_request_and_response_shape(self):
        first, headers, body = request_fixture("chat-original")
        self.assertEqual(first, b"POST /api/chat HTTP/1.1")
        self.assertEqual(int(headers[b"Content-Length"]), len(body))
        self.assertEqual(headers[b"Content-Type"], b"application/json")
        request = json.loads(body)
        self.assertFalse(request["stream"])
        self.assertEqual(request["messages"], [{"role": "user", "content": "Say hello."}])
        response = json.loads((FIXTURES / "chat-response.json").read_bytes())
        self.assertEqual(response["model"], request["model"])
        self.assertEqual(response["message"], {"role": "assistant", "content": "Hello."})
        self.assertTrue(response["done"])

    def test_requests_have_exact_byte_lengths_and_supported_api_shape(self):
        for name in ("generate-original", "generate-shorter", "generate-longer",
                     "generate-stream", "generate-alternate-target"):
            with self.subTest(name=name):
                first, headers, body = request_fixture(name)
                self.assertEqual(first, b"POST /api/generate HTTP/1.1")
                self.assertEqual(int(headers[b"Content-Length"]), len(body))
                self.assertEqual(headers[b"Content-Type"], b"application/json")
                address, port = headers[b"Host"].decode("ascii").rsplit(":", 1)
                self.assertEqual(ipaddress.ip_address(address).version, 4)
                self.assertGreaterEqual(int(port), 1)
                self.assertLessEqual(int(port), 65535)
                obj = json.loads(body)
                self.assertIsInstance(obj["model"], str)
                self.assertIsInstance(obj["prompt"], str)
                self.assertIs(type(obj["stream"]), bool)
                self.assertEqual(obj["stream"], name == "generate-stream")

    def test_edit_cases_change_length_and_preserve_other_fields(self):
        original = request_fixture("generate-original")[2]
        shorter = request_fixture("generate-shorter")[2]
        longer = request_fixture("generate-longer")[2]
        self.assertLess(len(shorter), len(original))
        self.assertGreater(len(longer), len(original))
        objects = [json.loads(body) for body in (original, shorter, longer)]
        for obj in objects:
            obj.pop("prompt")
        self.assertEqual(objects[0], objects[1])
        self.assertEqual(objects[0], objects[2])

    def test_nonstream_response_is_complete(self):
        response = json.loads((FIXTURES / "generate-response.json").read_bytes())
        self.assertTrue(response["done"])
        self.assertEqual(response["response"], "Hello.")

    def test_stream_contains_partial_records_and_final_completion(self):
        raw = (FIXTURES / "generate-response.ndjson").read_bytes()
        self.assertTrue(raw.endswith(b"\n"))
        records = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual([r["done"] for r in records], [False, False, True])
        self.assertEqual("".join(r["response"] for r in records), "Hello.")
        self.assertTrue(all(r["model"] == "synthetic-fixture-model" for r in records))


if __name__ == "__main__":
    unittest.main()
