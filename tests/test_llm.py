import json
import os
import sys
import tempfile
import threading
import types
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from vulnflow import llm
from vulnflow.correlate import Config
from vulnflow.llm import Analyst, LLMConfig, LLMError, Redactor, build_context, write_brief
from vulnflow.pipeline import run
from vulnflow.samples import generate


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.out = os.path.join(cls.tmp, "out")
        cls.res, _ = run(generate(os.path.join(cls.tmp, "in")), cls.out)


class VendorNeutralTests(Base):
    def test_no_default_provider(self):
        with mock.patch.dict(os.environ, {"VULNFLOW_LLM_PROVIDER": ""}):
            cfg = LLMConfig.from_env()
        self.assertFalse(cfg.ready)
        with self.assertRaises(LLMError):
            Analyst(self.res, cfg)

    def test_cli_requires_a_choice(self):
        from vulnflow.cli import main
        with mock.patch.dict(os.environ, {"VULNFLOW_LLM_PROVIDER": ""}):
            self.assertEqual(main(["ask", self.out, "--once", "hi"]), 2)


class ContextTests(Base):
    def test_context_is_stable_and_complete(self):
        a, b = build_context(self.res), build_context(self.res)
        self.assertEqual(a, b)                       # byte-identical => cacheable
        data = json.loads(a)
        total = len(self.res["findings"])
        self.assertEqual(len(data["findings"]), min(total, llm.MAX_FINDINGS_IN_CONTEXT))
        if total > llm.MAX_FINDINGS_IN_CONTEXT:     # the sample estate is larger than the cap
            self.assertIn(f"of {total} findings", data["note"])
        self.assertIn("connected back", " ".join(data["findings"][0]["indicators"]).replace("outbound connection(s) to", "connected back"))

    def test_local_context_is_compact_and_named_findings_are_added_on_demand(self):
        compact = build_context(self.res, compact=True)
        data = json.loads(compact)
        self.assertEqual(len(data["findings"]), llm.LOCAL_FINDINGS_IN_CONTEXT)
        self.assertLess(len(compact), 20000)
        self.assertIn("do not treat omitted findings as absent", data["note"])
        top_hosts = {r["host"] for r in self.res["findings"][:llm.LOCAL_FINDINGS_IN_CONTEXT]}
        target = next(r for r in self.res["findings"][llm.LOCAL_FINDINGS_IN_CONTEXT:]
                      if r["host"] not in top_hosts)
        captured = {}
        def local_reply(cfg, system, messages, effort):
            captured["system"], captured["question"] = system, messages[-1]["content"]
            return "Demo answer"
        with mock.patch.dict(llm.PROVIDERS, {"local": local_reply}):
            analyst = Analyst(self.res, LLMConfig.from_env(provider="local"))
            self.assertEqual(analyst.ask(f"What about {target['host']}?"), "Demo answer")
        self.assertIn(target["plugin_id"], captured["question"])
        self.assertIn("<focus_details>", captured["question"])
        self.assertLess(len(captured["system"]), len(Analyst(self.res, LLMConfig.from_env(provider="mock")).system) // 10)

    def test_focus_details_finds_hosts_and_cves(self):
        self.assertIn("97833", llm.focus_details(self.res, "Why is fs01 urgent?"))
        self.assertIn("10.10.3.31", llm.focus_details(self.res, "tell me about CVE-2019-0708"))
        self.assertEqual(llm.focus_details(self.res, "hello"), "")

    def test_redaction_round_trip(self):
        r = Redactor(self.res)
        ctx = build_context(self.res)
        red = r.apply(ctx)
        for secret in ("10.10.1.10", "203.0.113.45", "web01.corp.example", "fs01"):
            self.assertNotIn(secret, red)
        self.assertEqual(r.restore(red), ctx)
        self.assertNotIn("10.10.1.10", r.apply("see 10.10.1.10."))
        self.assertEqual(r.apply("Edge 129.0.2792.52 at 03:12:00"), "Edge 129.0.2792.52 at 03:12:00")

    def test_redaction_covers_free_text(self):
        import copy
        res = copy.deepcopy(self.res)
        res["findings"][0]["synopsis"] = ("Banner from 172.16.9.9 (fe80::1) names jump.corp.example and "
                                          "db-07.internal.lan; see www.apache.org; share on FS01")
        r = Redactor(res)
        out = r.apply(llm.focus_details(res, "web01"))
        for secret in ("172.16.9.9", "fe80::1", "jump.corp.example", "db-07.internal.lan", "FS01"):
            self.assertNotIn(secret, out)
        self.assertIn("www.apache.org", out)            # public reference sites stay readable
        self.assertIn("172.16.9.9", r.restore(out))

    def test_redaction_fails_closed(self):
        r = Redactor(self.res)
        with self.assertRaises(LLMError):
            r.verify("left over 10.10.1.10")


class FakeOpenAI(BaseHTTPRequestHandler):
    seen = []
    auth = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeOpenAI.seen.append(body)
        FakeOpenAI.auth.append(self.headers.get("Authorization"))
        # echo a redacted token back so we can check it is restored
        token = next((t for t in body["messages"][0]["content"].split('"') if t.startswith("INT-IP-")), "none")
        out = json.dumps({"choices": [{"message": {"content": f"Patch {token} first."}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


class OpenAICompatibleTests(Base):
    def test_redacted_request_to_local_endpoint(self):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeOpenAI)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            cfg = LLMConfig.from_env(provider="local", base_url=f"http://127.0.0.1:{srv.server_port}/v1",
                                     model="llama3.1", redact=True)
            answer = Analyst(self.res, cfg).ask("What should web01's owner do first?",
                                                [{"role": "assistant", "content": "orphan turn dropped"}])
        finally:
            srv.shutdown()
        sent = json.dumps(FakeOpenAI.seen[-1])
        self.assertNotIn("10.10.1.10", sent)
        self.assertNotIn("web01", sent)
        self.assertEqual([m["role"] for m in FakeOpenAI.seen[-1]["messages"]], ["system", "user"])
        self.assertRegex(answer, r"Patch 10\.\d+\.\d+\.\d+(/\d+)? first\.")

    def test_openai_provider_sends_key_and_current_params(self):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeOpenAI)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            cfg = LLMConfig.from_env(provider="openai", model="some-openai-model", api_key="sk-test-1234",
                                     base_url=f"http://127.0.0.1:{srv.server_port}/v1")
            Analyst(self.res, cfg).ask("hi")
        finally:
            srv.shutdown()
        self.assertEqual(FakeOpenAI.auth[-1], "Bearer sk-test-1234")
        self.assertIn("max_completion_tokens", FakeOpenAI.seen[-1])
        self.assertNotIn("temperature", FakeOpenAI.seen[-1])

    def test_openai_requires_model_and_key(self):
        with self.assertRaises(LLMError):
            LLMConfig.from_env(provider="openai")              # no model
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": ""}):
            cfg = LLMConfig.from_env(provider="openai", model="m")
            self.assertTrue(cfg.needs_key())

    def test_unreachable_endpoint_is_a_clean_error(self):
        cfg = LLMConfig.from_env(provider="local", base_url="http://127.0.0.1:9/v1")
        with self.assertRaises(LLMError):
            Analyst(self.res, cfg).ask("hi")


def _fake_anthropic(captured, stop_reason="end_turn", text="Brief text."):
    msg = types.SimpleNamespace(stop_reason=stop_reason, stop_details=None,
                                content=[types.SimpleNamespace(type="thinking", thinking=""),
                                         types.SimpleNamespace(type="text", text=text)])

    class Stream:
        def __init__(self, **kw):
            captured.update(kw)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get_final_message(self):
            return msg

    class Client:
        def __init__(self, **kw):
            self.beta = types.SimpleNamespace(messages=types.SimpleNamespace(stream=lambda **kw: Stream(**kw)))

    mod = types.ModuleType("anthropic")
    mod.Anthropic = Client
    for name in ("AuthenticationError", "NotFoundError", "RateLimitError", "APIStatusError", "APIConnectionError"):
        setattr(mod, name, type(name, (Exception,), {}))
    return mod


class AnthropicProviderTests(Base):
    def test_request_shape_and_brief_file(self):
        captured = {}
        with mock.patch.dict(sys.modules, {"anthropic": _fake_anthropic(captured)}):
            path = write_brief(self.res, self.out, LLMConfig.from_env(provider="anthropic"))
        self.assertEqual(captured["model"], "claude-opus-5-5")
        self.assertEqual(captured["fallbacks"], "default")
        self.assertEqual(captured["betas"], ["server-side-fallback-2026-07-01"])
        self.assertEqual(captured["system"][0]["cache_control"], {"type": "ephemeral"})
        self.assertIn("<correlation_results>", captured["system"][0]["text"])
        self.assertNotIn("thinking", captured)
        with open(path) as fh:
            self.assertIn("Brief text.", fh.read())
        self.assertTrue(os.path.exists(os.path.join(self.out, "ai_analyst_brief.html")))

    def test_refusal_becomes_llm_error(self):
        with mock.patch.dict(sys.modules, {"anthropic": _fake_anthropic({}, stop_reason="refusal")}):
            with self.assertRaises(LLMError):
                Analyst(self.res, LLMConfig.from_env(provider="anthropic")).ask("hi")


class WebTests(Base):
    def _server(self, llm_cfg):
        from vulnflow.web import make_handler
        runs = os.path.join(self.tmp, f"runs{id(llm_cfg)}")
        run_id = "0123456789abcdef"
        os.makedirs(os.path.join(runs, run_id))
        os.symlink(self.out, os.path.join(runs, run_id, "out"))
        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(runs, Config(), llm_cfg))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return f"http://127.0.0.1:{srv.server_port}", f"/runs/{run_id}/"

    def _post(self, url, data, headers=None):
        req = urllib.request.Request(url, data=data.encode(), headers=headers or {
            "Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def test_ask_endpoint_with_mock(self):
        host, run = self._server(LLMConfig.from_env(provider="mock"))
        with urllib.request.urlopen(host + run) as resp:
            page = resp.read().decode()
            self.assertIn("Ask about these results", page)
            self.assertIn('class="ai-chat-log" role="log"', page)
            self.assertIn("overflow-y:auto", page)
            self.assertIn("log.scrollTop = log.scrollHeight", page)
        with urllib.request.urlopen(host + run + "ai-status") as resp:
            self.assertEqual(resp.headers["Cache-Control"], "no-store")
            status = json.load(resp)
            self.assertTrue(status["enabled"])
            self.assertTrue(status["ready"])
            self.assertTrue(status["mock"])
            self.assertIn("nothing leaves this machine", status["description"])
        status, body = self._post(host + run + "ask", json.dumps({"question": "<b>fs01?</b>", "history": []}),
                                  {"Content-Type": "application/json"})
        j = json.loads(body)
        self.assertIn("&lt;b&gt;", j["answer_html"])   # model output is escaped
        self.assertNotIn("<b>", j["answer_html"])
        with open(os.path.join(self.out, "ai_chat_log.md")) as fh:
            self.assertIn("fs01?", fh.read())

    def test_mock_can_be_selected_in_browser_without_model_or_key(self):
        import re
        from urllib.parse import urlencode
        host, run = self._server(LLMConfig())
        with urllib.request.urlopen(host + "/settings?next=" + run) as resp:
            page = resp.read().decode()
        self.assertIn('<option value="mock">Offline mock</option>', page)
        token = re.search(r'name="csrf" value="([^"]+)"', page)[1]
        form = {"csrf": token, "next": run, "provider": "mock", "model": "old-model",
                "api_key": "unused-key", "action": "save"}
        status, body = self._post(host + "/settings", urlencode(form))
        self.assertEqual(status, 200)
        self.assertIn("Offline mock: fixed summaries", body)
        with urllib.request.urlopen(host + run + "ai-status") as resp:
            config = json.load(resp)
        self.assertTrue(config["ready"])
        self.assertTrue(config["mock"])

    def test_explorer_uses_same_run_chat_and_hides_it_when_ai_is_off(self):
        host, run = self._server(LLMConfig.from_env(provider="mock"))
        with urllib.request.urlopen(host + run + "explorer.html") as resp:
            page = resp.read().decode()
        self.assertIn('id="btn-ai"', page)
        self.assertIn('data-ai-chat data-ask-url="ask"', page)
        self.assertIn("ai-status", page)
        self.assertIn("(?:explorer\\.html)?", page)
        self.assertIn("analyst-chat", page)
        disabled_host, disabled_run = self._server(None)
        with urllib.request.urlopen(disabled_host + disabled_run + "ai-status") as resp:
            self.assertFalse(json.load(resp)["enabled"])

    def test_choose_provider_and_key_in_browser(self):
        import re
        from urllib.parse import urlencode
        with mock.patch.dict(os.environ, {"VULNFLOW_LLM_PROVIDER": "", "OPENAI_API_KEY": ""}):
            host, run = self._server(LLMConfig.from_env())
            with urllib.request.urlopen(host + run) as resp:
                self.assertIn("No AI provider selected", resp.read().decode())
            with urllib.request.urlopen(host + "/settings?next=" + run) as resp:
                page = resp.read().decode()
            token = re.search(r'name="csrf" value="([^"]+)"', page)[1]
            form = {"csrf": token, "next": run, "provider": "openai", "model": "", "api_key": "", "action": "save"}
            status, body = self._post(host + "/settings", urlencode(form))
            self.assertEqual(status, 400)                       # model required for OpenAI
            form.update(model="some-openai-model")
            status, body = self._post(host + "/settings", urlencode(form))
            self.assertIn("needs an API key", body)
            form.update(api_key="sk-secret-abcd")
            status, body = self._post(host + "/settings", urlencode(form))
            self.assertEqual(status, 200)                       # redirected back to the run page
            self.assertIn("OpenAI / some-openai-model", body)
            with urllib.request.urlopen(host + "/settings") as resp:
                page = resp.read().decode()
            self.assertNotIn("sk-secret-abcd", page)
            self.assertIn("…abcd", page)
            with urllib.request.urlopen(host + run + "ai-status") as resp:
                self.assertNotIn("sk-secret-abcd", resp.read().decode())
            status, _ = self._post(host + "/settings", urlencode({**form, "csrf": "wrong"}))
            self.assertEqual(status, 403)
            status, _ = self._post(host + "/settings", urlencode(form),
                                   {"Content-Type": "application/x-www-form-urlencoded", "Origin": "http://evil.example"})
            self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main()
