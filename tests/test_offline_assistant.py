import copy
import os
import tempfile
import unittest
from unittest import mock

from vulnflow import offline_assistant as oa
from vulnflow.llm import Analyst, LLMConfig, write_brief
from vulnflow.pipeline import run
from vulnflow.report import md_body
from vulnflow.samples import generate_bundles


class OfflineAssistantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        paths = generate_bundles(os.path.join(cls.tmp, "in"))
        cls.out = os.path.join(cls.tmp, "out")
        cls.res, _ = run([p for p in paths if "scan_and_telemetry" in p], cls.out)
        cls.tel, _ = run([p for p in paths if "telemetry_only" in p], os.path.join(cls.tmp, "tel"))

    def setUp(self):
        patcher = mock.patch("urllib.request.urlopen", side_effect=AssertionError("offline assistant used the network"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_brief_covers_the_main_sections(self):
        text = oa.brief(self.res)
        for heading in ("## Analyst take", "## What to do first", "## Likely attack paths",
                        "## How to validate the top findings", "## Where this analysis may be wrong"):
            self.assertIn(heading, text)
        self.assertIn("No AI model is used", text)
        self.assertIn("web01.corp.example (10.10.1.10): start incident response", text)
        self.assertIn("called back to 203.0.113.45", text)
        self.assertEqual(text, oa.brief(self.res))                  # deterministic

    def test_host_question_explains_rank_traffic_and_next_steps(self):
        text = oa.answer(self.res, "Why is web01 a P1?")
        self.assertIn("## web01.corp.example (10.10.1.10): P1", text)
        self.assertIn("**Why it ranks here**", text)
        self.assertIn("inbound and", text)
        self.assertIn("Vulnerable pivots", text)
        self.assertIn("( addr.src in 10.10.1.10 ) and ( addr.dst in 203.0.113.45 )", text)
        self.assertRegex(text, r"\n2\. Check every session")
        self.assertIn("**Log filters to paste:**", text)       # steps are numbered in order

    def test_follow_up_reuses_the_last_host(self):
        history = [{"role": "user", "content": "Why is web01 a P1?"}, {"role": "assistant", "content": "…"}]
        self.assertIn("## web01.corp.example", oa.answer(self.res, "how do I check it in Zeek?", history))
        self.assertNotIn("## web01.corp.example", oa.answer(self.res, "which IOCs matched", history))

    def test_cve_external_ip_and_topics(self):
        self.assertIn("web01.corp.example (10.10.1.10) | P1", oa.answer(self.res, "Which hosts have CVE-2021-41773?"))
        self.assertIn("## 203.0.113.45 (outside address)", oa.answer(self.res, "what about 203.0.113.45"))
        self.assertIn("## Outbound traffic worth a look", oa.answer(self.res, "show outbound callbacks"))
        self.assertIn("## Reached from the internet", oa.answer(self.res, "what is exposed to the internet?"))
        self.assertIn("## How scores and priorities work", oa.answer(self.res, "how is the score calculated"))
        self.assertIn("## What I can explain", oa.answer(self.res, "hello"))

    def test_telemetry_only_never_assigns_priorities(self):
        text = oa.brief(self.tel)
        self.assertIn("vulnerability status is unknown", text)
        self.assertNotRegex(text, r"\bP[1-4]\b")
        self.assertIn("## Leads to review", text)
        self.assertIn("No vulnerability data in this run", oa.answer(self.tel, "why is 10.10.1.10 flagged"))

    def test_untrusted_strings_cannot_break_markdown_or_html(self):
        res = copy.deepcopy(self.res)
        for r in res["findings"]:
            if r["host"] == "10.10.1.10":
                r["plugin_name"] = "Evil | <script>alert(1)</script>\n## Injected"
        html = md_body(oa.answer(res, "explain 10.10.1.10"))
        self.assertNotIn("<script>", html)
        self.assertNotIn("<h2>Injected", html)
        self.assertIn("Evil | &lt;script&gt;", html)

    def test_analyst_and_brief_file_use_the_offline_path(self):
        cfg = LLMConfig.offline()
        self.assertEqual(Analyst(self.res, cfg).system, "")
        self.assertIn("## web01", Analyst(self.res, cfg).ask("web01?"))
        write_brief(self.res, self.out, cfg)
        with open(os.path.join(self.out, "ai_analyst_brief.md")) as fh:
            self.assertIn("Built-in offline summary", fh.read())


if __name__ == "__main__":
    unittest.main()
