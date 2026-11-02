import json
import os
import re
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from email.message import Message
from unittest import mock

from vulnflow.article_brief import _assets, _validate, generate_article_briefs
from vulnflow.article_preview import _public_address, fetch_article_text
from vulnflow.llm import LLMConfig, LLMError
from vulnflow.pipeline import run
from vulnflow.report import save_article_briefs
from vulnflow.samples import generate
from vulnflow.correlate import Config
from vulnflow.web import make_handler


def valid_value(schema):
    kind = schema["type"]
    if "enum" in schema:
        return schema["enum"][0]
    if kind == "object":
        return {key: valid_value(schema["properties"][key]) for key in schema["required"]}
    if kind == "array":
        return [valid_value(schema["items"]) for _ in range(schema.get("minItems", 0))]
    if kind == "string":
        return "Source-supported text."
    if kind == "number":
        return 0.8
    if kind == "boolean":
        return False
    raise AssertionError(kind)


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def read(self, _limit):
        return self.payload


class ArticleBriefTests(unittest.TestCase):
    def test_exact_prompt_schema_and_one_call_per_article(self):
        prompt, schema = _assets()
        self.assertIn("Treat article_text", prompt)
        self.assertIn("executive_summary", schema["schema"]["required"])
        url = "https://research.example/ip-case"
        output = valid_value(schema["schema"])
        output["executive_summary"] = "Source-backed brief for the matched IP."
        output["iocs"]["ips"] = ["8.8.8.8"]
        response = {"output": [{"type": "message", "content": [{"type": "output_text",
                     "text": json.dumps(output)}]}]}
        seen = []

        def fake_urlopen(request, timeout):
            seen.append((request, timeout))
            return FakeResponse(json.dumps(response).encode())

        res = {"ioc_matches": [
            {"value": "8.8.8.8", "articles": [url]},
            {"value": "CVE-2024-21887", "articles": [url]},
        ]}
        cfg = LLMConfig.from_env(provider="openai", model="test-model", api_key="sk-test-only")
        with mock.patch("vulnflow.article_brief.fetch_article_text",
                        return_value={"title": "Research note", "text": "Article evidence mentions 8.8.8.8. " * 20}), \
             mock.patch("vulnflow.article_brief.urllib.request.urlopen", side_effect=fake_urlopen):
            summary = generate_article_briefs(res, cfg)
            second = generate_article_briefs(res, cfg)
        self.assertEqual((summary["generated"], second["generated"]), (1, 0))
        self.assertEqual(len(seen), 1)
        body = json.loads(seen[0][0].data)
        self.assertEqual(body["text"]["format"]["name"], "mucaro_threat_analysis")
        self.assertIn("8.8.8.8", body["input"][1]["content"][0]["text"])
        self.assertEqual(seen[0][0].get_header("Authorization"), "Bearer sk-test-only")
        self.assertEqual(res["article_briefs"][url]["brief"]["source"]["url"], url)
        self.assertNotIn("sk-test-only", json.dumps(res))

    def test_validation_and_source_protection(self):
        _, schema = _assets()
        invalid = valid_value(schema["schema"])
        del invalid["iocs"]
        with self.assertRaises(LLMError):
            _validate(invalid, schema["schema"])
        self.assertIsNone(_public_address("http://127.0.0.1/internal"))
        with self.assertRaises(LLMError):
            generate_article_briefs({"ioc_matches": [{"value": "8.8.8.8", "articles": ["https://x.example/a"]}]},
                                    LLMConfig(provider="openai", model="test-model", api_key="test", redact=True))

    def test_public_article_fetch_extracts_text_without_page_code(self):
        class Response:
            status = 200
            headers = Message()
            headers["Content-Type"] = "text/html; charset=utf-8"

            def read(self, _limit):
                return (b"<html><head><title>Incident report</title><script>secret script</script></head>"
                        b"<body><nav>menu content</nav><article><h1>Incident report</h1>"
                        b"<p>Researchers reported traffic to 8.8.8.8 during the incident.</p>"
                        b"</article></body></html>")

        class Connection:
            def request(self, *_args, **_kwargs):
                pass

            def getresponse(self):
                return Response()

            def close(self):
                pass

        with mock.patch("vulnflow.article_preview._public_address",
                        return_value=("research.example", 443, "93.184.215.14", "/report")), \
             mock.patch("vulnflow.article_preview.http.client.HTTPSConnection", return_value=Connection()):
            article = fetch_article_text("https://research.example/report")
        self.assertEqual(article["title"], "Incident report")
        self.assertIn("8.8.8.8", article["text"])
        self.assertNotIn("secret script", article["text"])
        self.assertNotIn("menu content", article["text"])

    def test_saved_brief_updates_all_three_standalone_views(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = os.path.join(tmp, "mucaro-archive.csv")
            url = "https://research.example/ip-case"
            with open(archive, "w", encoding="utf-8") as fh:
                fh.write("indicatorType,indicator,articleUrls\n" + f"ip,8.8.8.8,{url}\n")
            with mock.patch("vulnflow.article_preview.fetch_preview",
                            return_value={"title": "Research note", "overview": "Short source preview."}):
                res, _ = run(generate(os.path.join(tmp, "in")) + [archive], os.path.join(tmp, "out"))
            self.assertTrue(res["ioc_matches"])
            _, schema = _assets()
            brief = valid_value(schema["schema"])
            brief["executive_summary"] = "Source-backed brief for the matched IP."
            brief["source"]["url"] = url
            res["article_briefs"] = {url: {"brief": brief, "model": "test-model"}}
            save_article_briefs(res, os.path.join(tmp, "out"))
            for name in ("executive_summary.html", "technical_report.html", "explorer.html"):
                with open(os.path.join(tmp, "out", name), encoding="utf-8") as fh:
                    page = fh.read()
                self.assertIn("Source-backed brief for the matched IP.", page)
                self.assertIn("Múcaro AI Brief", page)
                self.assertIn("Exact IOC match", page)
            with open(os.path.join(tmp, "out", "results.json"), encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["article_briefs"][url]["brief"]["source"]["url"], url)

    def test_web_action_generates_saved_brief_with_existing_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_id = "0123456789abcdef"
            out = os.path.join(tmp, "runs", run_id, "out")
            os.makedirs(out)
            url = "https://research.example/ip-case"
            archive = os.path.join(tmp, "mucaro-archive.csv")
            with open(archive, "w", encoding="utf-8") as fh:
                fh.write("indicatorType,indicator,articleUrls\n" + f"ip,8.8.8.8,{url}\n")
            with mock.patch("vulnflow.article_preview.fetch_preview",
                            return_value={"title": "Research note", "overview": "Short source preview."}):
                run(generate(os.path.join(tmp, "in")) + [archive], out)
            cfg = LLMConfig.from_env(provider="openai", model="test-model", api_key="sk-test-only")
            server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(os.path.join(tmp, "runs"), Config(), cfg))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}/runs/{run_id}/"
            try:
                with urllib.request.urlopen(base) as response:
                    index = response.read().decode()
                self.assertIn("Generate article briefs with OpenAI", index)
                self.assertIn('class="article-brief-progress"', index)
                self.assertIn('class="analyst-chat results-assistant-drawer"', index)
                csrf = re.search(r'action="article-briefs"><input type="hidden" name="csrf" value="([^"]+)', index)
                self.assertIsNotNone(csrf)

                def fake_generate(res, llm_cfg):
                    self.assertEqual(llm_cfg.api_key, "sk-test-only")
                    _, schema = _assets()
                    brief = valid_value(schema["schema"])
                    brief["executive_summary"] = "Saved article brief from the local web action."
                    res["article_briefs"] = {url: {"brief": brief, "model": llm_cfg.model}}
                    return {"generated": 1, "saved": 1, "unavailable": 0, "errors": []}

                body = urllib.parse.urlencode({"csrf": csrf.group(1)}).encode()
                with mock.patch("vulnflow.web.generate_article_briefs", side_effect=fake_generate):
                    with urllib.request.urlopen(urllib.request.Request(base + "article-briefs", body)) as response:
                        self.assertIn("Generated 1 brief", response.read().decode())
                with urllib.request.urlopen(base + "explorer.html") as response:
                    self.assertIn("Saved article brief from the local web action.", response.read().decode())
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
