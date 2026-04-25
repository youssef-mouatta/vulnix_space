import json
import os
import unittest

os.environ["GOOGLE_API_KEY"] = ""
os.environ.setdefault("FLASK_ENV", "development")

from werkzeug.security import generate_password_hash

from config import Config

Config.SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
Config.TESTING = True

from app import create_app
from models import ScanResult, User, db
import routes.report as report_module
import scanner as scanner_module
import ai_service as ai_module
from utils.plan_limits import apply_plan_limits


class VulnixAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        report_module.get_scan_summary = lambda *args, **kwargs: {"response": "stub summary"}
        cls.app = create_app()

    def setUp(self):
        self.client = self.app.test_client()
        with self.app.app_context():
            db.drop_all()
            db.create_all()

            user = User(
                username="tester",
                email="tester@example.com",
                password=generate_password_hash("pass123", method="pbkdf2:sha256"),
                tier="Free",
            )
            db.session.add(user)
            db.session.commit()

            scan = ScanResult(
                user_id=user.id,
                url="https://example.com",
                score="95",
                issues_json=json.dumps(
                    [
                        {
                            "name": "Open Redirect Vulnerability",
                            "severity": "HIGH",
                            "category": "Injection",
                            "impact": "Redirect can be abused.",
                            "fix": "Whitelist redirects.",
                            "confidence": "High",
                            "classification": "REAL_RISK",
                            "poc": "https://example.com?next=https://evil.com",
                        }
                    ]
                ),
                explanation_json=json.dumps(
                    {
                        "scan_failed": False,
                        "is_limited": False,
                        "has_issues": True,
                        "risk_level": "High",
                    }
                ),
                is_public=False,
            )
            db.session.add(scan)
            db.session.commit()

            self.scan_id = scan.id

    def login(self):
        return self.client.post(
            "/login",
            data={"username": "tester", "password": "pass123"},
            follow_redirects=False,
        )

    def test_public_pages_load(self):
        for path in ["/", "/pricing", "/login", "/register"]:
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)

    def test_dashboard_requires_login(self):
        response = self.client.get("/dashboard", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_login_then_dashboard_works(self):
        login_response = self.login()
        self.assertEqual(login_response.status_code, 302)

        dashboard_response = self.client.get("/dashboard")
        self.assertEqual(dashboard_response.status_code, 200)
        self.assertIn("Run a Vulnix Scan", dashboard_response.get_data(as_text=True))

    def test_private_report_redirects_anonymous_users_to_login(self):
        response = self.client.get(f"/report/{self.scan_id}", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_authenticated_user_can_open_private_report(self):
        self.login()
        response = self.client.get(f"/report/{self.scan_id}")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Open Redirect Vulnerability", response.get_data(as_text=True))

    def test_report_chat_requires_message(self):
        self.login()
        response = self.client.post(f"/api/chat/{self.scan_id}", json={})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "missing_message")

    def test_free_tier_chat_limit_is_enforced(self):
        self.login()
        original_chat = report_module.chat_about_scan
        report_module.chat_about_scan = lambda *args, **kwargs: {"response": "RISK: test\nIMPACT: test\nFIX: test\nPRIORITY: Fix Soon"}
        try:
            for _ in range(5):
                ok = self.client.post(f"/api/chat/{self.scan_id}", json={"message": "what first"})
                self.assertEqual(ok.status_code, 200)
                self.assertIn("remaining", ok.get_json())

            limited = self.client.post(f"/api/chat/{self.scan_id}", json={"message": "one more"})
            self.assertEqual(limited.status_code, 402)
            payload = limited.get_json()
            self.assertEqual(payload["error"], "limit_reached")
            self.assertEqual(payload["remaining"], 0)
        finally:
            report_module.chat_about_scan = original_chat

    def test_toggle_share_works_for_owner(self):
        self.login()
        response = self.client.post(f"/api/share/{self.scan_id}")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["is_public"])

    def test_plan_limits_do_not_mutate_original_issues(self):
        issues = [
            {
                "name": "Issue 1",
                "category": "Injection",
                "poc": "real-poc",
            }
        ]

        free_view = apply_plan_limits("Free", issues)
        business_view = apply_plan_limits("Business", issues)

        self.assertEqual(free_view[0]["poc"], "Upgrade to Business for PoC")
        self.assertEqual(business_view[0]["poc"], "real-poc")
        self.assertEqual(issues[0]["poc"], "real-poc")

    def test_scanner_blocks_private_target(self):
        issues, score, risk, _, _ = scanner_module.scan_website("http://127.0.0.1")
        self.assertEqual(score, "0")
        self.assertEqual(risk, "High")
        self.assertEqual(issues[0]["name"], "Private Network Target Blocked")

    def test_detect_chains_recognizes_current_issue_names(self):
        original_simulate_xss = scanner_module.simulate_xss
        original_check_sensitive_files = scanner_module.check_sensitive_files
        original_check_open_redirect = scanner_module.check_open_redirect
        original_detect_chains = scanner_module.detect_chains
        original_probe = scanner_module.probe_network_info
        original_session = scanner_module.requests.Session

        class Cookie:
            name = "sessionid"
            secure = False
            _rest = {}

            def has_nonstandard_attr(self, _):
                return False

        class FakeResponse:
            def __init__(self):
                self.url = "https://example.com"
                self.status_code = 200
                self.headers = {"Content-Type": "text/html"}
                self.text = "<html>ok</html>"

        class FakeSession:
            def __init__(self):
                self.headers = {}
                self.cookies = [Cookie()]

            def get(self, *_args, **_kwargs):
                return FakeResponse()

        scanner_module.simulate_xss = lambda *_a, **_k: {"level": "medium", "evidence": "<script>"}
        scanner_module.check_sensitive_files = lambda *_a, **_k: []
        scanner_module.check_open_redirect = lambda *_a, **_k: {"found": False}
        scanner_module.detect_chains = original_detect_chains
        scanner_module.probe_network_info = lambda *_a, **_k: {"ip": None, "open_ports": []}
        scanner_module.requests.Session = FakeSession
        scanner_module._cache.clear()
        try:
            issues, *_ = scanner_module.scan_website("https://example.com")
            names = [i["name"] for i in issues]
            self.assertIn("Injection -> Cookie Theft -> Session Hijack", names)
        finally:
            scanner_module.simulate_xss = original_simulate_xss
            scanner_module.check_sensitive_files = original_check_sensitive_files
            scanner_module.check_open_redirect = original_check_open_redirect
            scanner_module.detect_chains = original_detect_chains
            scanner_module.probe_network_info = original_probe
            scanner_module.requests.Session = original_session

    def test_ai_validate_output_requires_structured_findings(self):
        bad = "RISK: x\nFIX: y"
        self.assertFalse(ai_module.validate_output(bad, "[]", is_findings=True))
        good = "RISK: x\nIMPACT: y\nFIX: z\nPRIORITY: Fix Soon"
        self.assertTrue(ai_module.validate_output(good, "[]", is_findings=True))


if __name__ == "__main__":
    unittest.main()
