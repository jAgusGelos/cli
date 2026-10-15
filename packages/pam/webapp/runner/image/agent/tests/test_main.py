import json
import unittest

from _path import AGENT  # noqa: F401
from iwa_agent.live import annexb_nals, codec_from_annexb, nal_types
from iwa_agent.main import format_log, load_config, redact

ENV = {
    "IWA_SESSION_ID": "8a0c6a4e-1f7b-4e0e-9a43-5d2a6f0b9c11",
    "IWA_RUNNER_TOKEN": "c2VjcmV0LXRva2VuLXZhbHVlLTEyMzQ1Njc4OTA",
    "IWA_GATEWAY_AGENT_ADDR": "172.28.0.1:17701",
    "IWA_PROXY_ADDR": "172.28.0.1:13128",
    "IWA_START_URL": "https://app.corp.internal/input",
    "IWA_ALLOWED_HOSTS": '["app.corp.internal"]',
    "IWA_CA_PEM": "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----",
    "IWA_POLICY": '{"clipboard":"off"}',
    "IWA_DISPLAY": "1280x720@30",
    "IWA_RECORDING": '{"segmentSeconds":10,"bitrateKbps":1500,"crf":26}',
    "IWA_WATERMARK": "admin@infisical.local 8a0c6a4e",
    "IWA_IMAGE_DIGEST": "sha256:" + "ab" * 32,
}


class RedactionTest(unittest.TestCase):
    def test_redacts_secrets_recursively(self):
        line = format_log("info", "x", {"password": "hunter2", "runnerToken": "tok", "nested": {"caPem": "PEM",
                          "list": [{"Password": "p2"}]}, "user": "alice"})
        rec = json.loads(line)
        self.assertNotIn("hunter2", line)
        self.assertNotIn("tok\"", line)
        self.assertNotIn("PEM", line)
        self.assertNotIn("p2", line)
        self.assertEqual(rec["password"], "[redacted]")
        self.assertEqual(rec["nested"]["caPem"], "[redacted]")
        self.assertEqual(rec["user"], "alice")
        self.assertEqual(rec["event"], "x")

    def test_env_names(self):
        self.assertEqual(redact({"IWA_RUNNER_TOKEN": "a", "IWA_CA_PEM": "b"}),
                         {"IWA_RUNNER_TOKEN": "[redacted]", "IWA_CA_PEM": "[redacted]"})


class ConfigTest(unittest.TestCase):
    def test_valid(self):
        cfg = load_config(ENV)
        self.assertEqual((cfg.width, cfg.height, cfg.fps), (1280, 720, 30))
        self.assertEqual((cfg.segment_seconds, cfg.bitrate_kbps, cfg.crf), (10, 1500, 26))
        self.assertEqual(cfg.allowed_hosts, ["app.corp.internal"])

    def test_invalid(self):
        bad = [("IWA_DISPLAY", "1280x720"), ("IWA_SESSION_ID", "nope"), ("IWA_GATEWAY_AGENT_ADDR", "host:1"),
               ("IWA_IMAGE_DIGEST", "sha256:xyz"), ("IWA_RECORDING", '{"crf":99}'), ("IWA_RUNNER_TOKEN", "")]
        for key, value in bad:
            with self.subTest(key):
                env = dict(ENV, **{key: value})
                with self.assertRaises(ValueError):
                    load_config(env)


class AnnexBTest(unittest.TestCase):
    def test_nals_and_codec(self):
        data = b"\0\0\0\1\x67\x42\xc0\x1f\xaa\0\0\0\1\x68\xce\0\0\1\x65\x88"
        self.assertEqual(nal_types(data), [7, 8, 5])
        self.assertEqual(len(annexb_nals(data)), 3)
        self.assertEqual(codec_from_annexb(data), "avc1.42C01F")


if __name__ == "__main__":
    unittest.main()
