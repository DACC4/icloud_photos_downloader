import inspect
import json
import logging
import os
from typing import Any, List, Mapping, NamedTuple, Sequence
from unittest import TestCase, mock

import pytest

from icloudpd.authentication import (
    PHOTOS_ACCESS_ATTEMPTS,
    PHOTOS_ACCESS_INTERVAL_SECONDS,
    request_photos_access,
    request_security_key,
)
from pyicloud_ipd.exceptions import PyiCloudFailedMFAException, PyiCloudNoSecurityKeyException
from pyicloud_ipd.security_key import (
    SecurityKeyChallenge,
    WebAuthnAssertion,
    build_security_key_options_request,
    build_verify_security_key_request,
    get_assertion_from_device,
    parse_security_key_challenge,
)
from pyicloud_ipd.sms import AuthenticatedSession
from tests.helpers import path_from_project_root, recreate_path, run_cassette

CHALLENGE = SecurityKeyChallenge(
    challenge="Y2hhbGxlbmdlLTEyMzQ1Njc4OTA",
    key_handles=["a2V5aGFuZGxlLTEyMzQ1Njc4OTA"],
    rp_id="apple.com",
    key_names=["Dummy Key"],
)

ASSERTION = WebAuthnAssertion(
    client_data=b"client-data",
    authenticator_data=b"authenticator-data",
    signature=b"signature",
    user_handle=None,
    credential_id=b"credential-id",
)


class _Context(NamedTuple):
    domain: str
    oauth_session: AuthenticatedSession


CONTEXT = _Context(
    domain="com",
    oauth_session=AuthenticatedSession(client_id="client", scnt="scnt", session_id="session"),
)


class _FakeService:
    def __init__(self, valid: bool) -> None:
        self.valid = valid
        self.validated: Sequence[SecurityKeyChallenge] = []

    def validate_security_key(self, challenge: SecurityKeyChallenge, _get_assertion: Any) -> bool:
        self.validated = [challenge]
        return self.valid


class SecurityKeyTestCase(TestCase):
    @pytest.fixture(autouse=True)
    def inject_fixtures(self) -> None:
        self.root_path = path_from_project_root(__file__)
        self.fixtures_path = os.path.join(self.root_path, "fixtures")
        self.vcr_path = os.path.join(self.root_path, "vcr_cassettes")

    def test_parse_challenge_without_key_names(self) -> None:
        result = parse_security_key_challenge(
            {"fsaChallenge": {"challenge": "c", "keyHandles": ["k"], "rpId": "apple.com"}}
        )
        self.assertEqual(
            result,
            SecurityKeyChallenge(challenge="c", key_handles=["k"], rp_id="apple.com", key_names=[]),
        )

    def test_build_options_request(self) -> None:
        req = build_security_key_options_request(CONTEXT)
        self.assertEqual(req.method, "GET")
        self.assertEqual(req.url, "https://idmsa.apple.com/appleauth/auth")
        self.assertEqual(req.headers["Accept"], "application/json")
        self.assertEqual(req.headers["scnt"], "scnt")

    def test_build_verify_request(self) -> None:
        req = build_verify_security_key_request(
            _Context(domain="cn", oauth_session=CONTEXT.oauth_session), CHALLENGE, ASSERTION
        )
        self.assertEqual(req.method, "POST")
        self.assertEqual(req.url, "https://idmsa.apple.com.cn/appleauth/auth/verify/security/key")
        self.assertEqual(
            req.json,
            {
                "challenge": "Y2hhbGxlbmdlLTEyMzQ1Njc4OTA",
                "rpId": "apple.com",
                "clientData": "Y2xpZW50LWRhdGE=",
                "authenticatorData": "YXV0aGVudGljYXRvci1kYXRh",
                "signatureData": "c2lnbmF0dXJl",
                "userHandle": None,
                "credentialID": "Y3JlZGVudGlhbC1pZA==",
            },
        )

    def test_build_verify_request_with_user_handle(self) -> None:
        req = build_verify_security_key_request(
            CONTEXT, CHALLENGE, ASSERTION._replace(user_handle=b"user")
        )
        assert req.json is not None
        self.assertEqual(req.json["userHandle"], "dXNlcg==")
        # must be serializable for the request
        json.dumps(req.json)

    def test_request_security_key_success(self) -> None:
        service = _FakeService(True)
        request_security_key(service, logging.getLogger("test"), CHALLENGE)  # type: ignore[arg-type]
        self.assertEqual(service.validated, [CHALLENGE])

    def test_request_security_key_failed_verification(self) -> None:
        service = _FakeService(False)
        with self.assertRaises(PyiCloudFailedMFAException) as context:
            request_security_key(
                service,  # type: ignore[arg-type]
                logging.getLogger("test"),
                CHALLENGE._replace(key_names=[]),
            )
        self.assertIn("Failed to verify security key", str(context.exception))

    def test_get_assertion_without_device(self) -> None:
        with (
            mock.patch("sys.platform", "linux"),
            mock.patch("fido2.hid.CtapHidDevice.list_devices", return_value=iter([])),
            self.assertRaises(PyiCloudNoSecurityKeyException) as context,
        ):
            get_assertion_from_device(CHALLENGE)
        self.assertIn("--auth-only", str(context.exception))

    def test_2fa_flow_security_key(self) -> None:
        base_dir = os.path.join(self.fixtures_path, inspect.stack()[0][3])
        cookie_dir = os.path.join(base_dir, "cookie")

        for dir in [base_dir, cookie_dir]:
            recreate_path(dir)

        with mock.patch(
            "icloudpd.authentication.default_get_assertion", return_value=ASSERTION
        ) as get_assertion:
            result = run_cassette(
                os.path.join(self.vcr_path, "2fa_flow_security_key.yml"),
                [
                    "--username",
                    "jdoe@gmail.com",
                    "--password",
                    "password1",
                    "--no-progress-bar",
                    "--cookie-directory",
                    cookie_dir,
                    "--auth-only",
                ],
            )
        get_assertion.assert_called_once_with(CHALLENGE)
        self.assertIn("Two-factor authentication is required", result.output)
        self.assertIn(
            "Connect one of your security keys (Dummy Key) to this machine", result.output
        )
        self.assertNotIn("Please enter two-factor authentication code", result.output)
        self.assertIn(
            "Great, you're all set up. The script can now be run without "
            "user interaction until 2FA expires.",
            result.output,
        )
        self.assertEqual(result.exit_code, 0, "exit code")

    def test_2fa_flow_security_key_rejected(self) -> None:
        base_dir = os.path.join(self.fixtures_path, inspect.stack()[0][3])
        cookie_dir = os.path.join(base_dir, "cookie")

        for dir in [base_dir, cookie_dir]:
            recreate_path(dir)

        with mock.patch("icloudpd.authentication.default_get_assertion", return_value=ASSERTION):
            result = run_cassette(
                os.path.join(self.vcr_path, "2fa_flow_security_key_rejected.yml"),
                [
                    "--username",
                    "jdoe@gmail.com",
                    "--password",
                    "password1",
                    "--no-progress-bar",
                    "--cookie-directory",
                    cookie_dir,
                    "--auth-only",
                ],
            )
        self.assertIn("Failed to verify security key", result.output)
        self.assertEqual(result.exit_code, 1, "exit code")


class _FakePcsService:
    def __init__(
        self, consent_states: Sequence[bool], responses: Sequence[Mapping[str, Any]]
    ) -> None:
        self.consent_states = list(consent_states)
        self.responses = list(responses)
        self.consent_requests = 0
        self.pcs_requests = 0
        self.granted = False

    def request_web_access_state(self) -> Mapping[str, Any]:
        consented = (
            self.consent_states.pop(0) if len(self.consent_states) > 1 else self.consent_states[0]
        )
        return {"isDeviceConsentedForPCS": consented}

    def enable_device_consent_for_pcs(self) -> Mapping[str, Any]:
        self.consent_requests += 1
        return {}

    def request_pcs(self, app_name: str) -> Mapping[str, Any]:
        self.pcs_requests += 1
        response = self.responses.pop(0) if self.responses else {"status": "failure"}
        self.granted = response.get("status") == "success"
        return response

    def has_photos_pcs_cookies(self) -> bool:
        return self.granted


class PhotosAccessTestCase(TestCase):
    def test_granted_after_device_approval(self) -> None:
        # not consented: request consent, then poll until consented before requesting keys
        service = _FakePcsService([False, False, True], [{"status": "success"}])
        sleeps: List[float] = []
        request_photos_access(service, logging.getLogger("test"), sleeps.append)  # type: ignore[arg-type]
        # a single approval request reaches the devices, keys are requested only once consented
        self.assertEqual(service.consent_requests, 1)
        self.assertEqual(service.pcs_requests, 1)
        self.assertEqual(sleeps, [PHOTOS_ACCESS_INTERVAL_SECONDS])

    def test_already_consented(self) -> None:
        service = _FakePcsService([True], [{"status": "success"}])
        request_photos_access(service, logging.getLogger("test"), lambda _: None)  # type: ignore[arg-type]
        self.assertEqual(service.consent_requests, 0)

    def test_keys_not_released_at_first(self) -> None:
        service = _FakePcsService([True], [{}, {"status": "success"}])
        sleeps: List[float] = []
        request_photos_access(service, logging.getLogger("test"), sleeps.append)  # type: ignore[arg-type]
        self.assertEqual(service.pcs_requests, 2)

    def test_not_approved(self) -> None:
        service = _FakePcsService([False], [])
        sleeps: List[float] = []
        with self.assertRaises(PyiCloudFailedMFAException) as context:
            request_photos_access(service, logging.getLogger("test"), sleeps.append)  # type: ignore[arg-type]
        self.assertIn("not approved", str(context.exception))
        # waiting the whole time must not send more approval requests
        self.assertEqual(service.consent_requests, 1)
        self.assertEqual(service.pcs_requests, 0)
        self.assertEqual(len(sleeps), PHOTOS_ACCESS_ATTEMPTS - 1)
