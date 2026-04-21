import json
import unittest

from werkzeug.security import generate_password_hash

from config import Config

Config.SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
Config.TESTING = True

from app import create_app
from models import ScanResult, User, db
import routes.report as report_module
from routes.scan import apply_plan_limits


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


if __name__ == "__main__":
    unittest.main()
