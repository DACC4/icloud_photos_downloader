"""FIDO2 security key (WebAuthn) support for Apple's two-factor authentication"""

import base64
import sys
from typing import Any, Callable, Mapping, NamedTuple, Sequence

from pyicloud_ipd.exceptions import PyiCloudFailedMFAException, PyiCloudNoSecurityKeyException
from pyicloud_ipd.sms import (
    Request,
    _auth_url,
    _InternalRequest,
    _oauth_const_headers,
    _oauth_headers,
    _oauth_redirect_header,
    _TrustedPhoneContextProvider,
)


class SecurityKeyChallenge(NamedTuple):
    challenge: str
    key_handles: Sequence[str]
    rp_id: str
    key_names: Sequence[str]


class WebAuthnAssertion(NamedTuple):
    client_data: bytes
    authenticator_data: bytes
    signature: bytes
    user_handle: bytes | None
    credential_id: bytes


def parse_security_key_challenge(payload: Mapping[str, Any]) -> SecurityKeyChallenge | None:
    """Extracts the WebAuthn challenge from the auth options returned by Apple

    >>> parse_security_key_challenge(
    ...     {
    ...         "fsaChallenge": {"challenge": "c", "keyHandles": ["k"], "rpId": "apple.com"},
    ...         "keyNames": ["Yubi"],
    ...     }
    ... )
    SecurityKeyChallenge(challenge='c', key_handles=['k'], rp_id='apple.com', key_names=['Yubi'])
    >>> parse_security_key_challenge({"fsaChallenge": {"challenge": "c"}}) is None
    True
    >>> parse_security_key_challenge({}) is None
    True
    """
    fsa = payload.get("fsaChallenge")
    if not isinstance(fsa, Mapping):
        return None
    challenge = fsa.get("challenge")
    key_handles = fsa.get("keyHandles")
    rp_id = fsa.get("rpId")
    if not challenge or not key_handles or not rp_id:
        return None
    return SecurityKeyChallenge(
        challenge=challenge,
        key_handles=key_handles,
        rp_id=rp_id,
        key_names=payload.get("keyNames") or [],
    )


def build_security_key_options_request(context: _TrustedPhoneContextProvider) -> Request:
    """Builds a request for the WebAuthn challenge of the security key 2fa"""

    return _InternalRequest(
        method="GET",
        url=_auth_url(context.domain),
        headers={
            **_oauth_const_headers(),
            **_oauth_redirect_header(context.domain),
            **_oauth_headers(context.oauth_session),
            **{"Accept": "application/json"},
        },
    )


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode()


def build_verify_security_key_request(
    context: _TrustedPhoneContextProvider,
    challenge: SecurityKeyChallenge,
    assertion: WebAuthnAssertion,
) -> Request:
    """Builds a request submitting the WebAuthn assertion of the security key 2fa"""

    json = {
        "challenge": challenge.challenge,
        "rpId": challenge.rp_id,
        "clientData": _b64(assertion.client_data),
        "authenticatorData": _b64(assertion.authenticator_data),
        "signatureData": _b64(assertion.signature),
        "userHandle": _b64(assertion.user_handle) if assertion.user_handle else None,
        "credentialID": _b64(assertion.credential_id),
    }

    return _InternalRequest(
        method="POST",
        url=_auth_url(context.domain) + "/verify/security/key",
        headers={
            **_oauth_const_headers(),
            **_oauth_redirect_header(context.domain),
            **_oauth_headers(context.oauth_session),
            **{"Content-type": "application/json; charset=utf-8"},
            **{"Accept": "application/json; charset=utf-8"},
        },
        json=json,
    )


def _b64url_decode(value: str) -> bytes:
    """Decodes base64 or base64url with or without padding

    >>> _b64url_decode("-_8")
    b'\\xfb\\xff'
    >>> _b64url_decode("+/8=")
    b'\\xfb\\xff'
    """
    normalized = value.replace("+", "-").replace("/", "_").rstrip("=")
    return base64.urlsafe_b64decode(normalized + "=" * (-len(normalized) % 4))


NO_SECURITY_KEY_MESSAGE = (
    "No FIDO2 security key found. Plug in your security key; on Linux make sure the "
    "current user can access /dev/hidraw* devices (udev rules), in Docker pass the device "
    "into the container. Alternatively authenticate on a machine with the key using "
    "--auth-only and copy the cookie directory to this machine."
)


def get_assertion_from_device(
    challenge: SecurityKeyChallenge, prompt_up: Callable[[], None] = lambda: None
) -> WebAuthnAssertion:  # pragma: no cover - requires hardware
    """Performs the WebAuthn assertion ceremony with a connected FIDO2 security key"""
    from fido2.client import ClientError, DefaultClientDataCollector, Fido2Client, UserInteraction
    from fido2.webauthn import (
        AuthenticationResponse,
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialRequestOptions,
        PublicKeyCredentialType,
        UserVerificationRequirement,
    )

    collector = DefaultClientDataCollector(f"https://{challenge.rp_id}")
    options = PublicKeyCredentialRequestOptions(
        challenge=_b64url_decode(challenge.challenge),
        rp_id=challenge.rp_id,
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                type=PublicKeyCredentialType.PUBLIC_KEY, id=_b64url_decode(handle)
            )
            for handle in challenge.key_handles
        ],
        user_verification=UserVerificationRequirement.DISCOURAGED,
    )

    result: AuthenticationResponse
    if sys.platform == "win32":
        from fido2.client.windows import WindowsClient

        if WindowsClient.is_available():
            prompt_up()
            try:
                result = WindowsClient(collector).get_assertion(options).get_response(0)
            except ClientError as error:
                raise PyiCloudFailedMFAException(
                    f"Security key assertion failed: {error}"
                ) from error
            return _to_assertion(result)

    from fido2.hid import CtapHidDevice

    devices = list(CtapHidDevice.list_devices())
    if not devices:
        raise PyiCloudNoSecurityKeyException(NO_SECURITY_KEY_MESSAGE)

    class _Interaction(UserInteraction):
        def prompt_up(self) -> None:
            prompt_up()

    client = Fido2Client(devices[0], collector, user_interaction=_Interaction())
    try:
        result = client.get_assertion(options).get_response(0)
    except ClientError as error:
        raise PyiCloudFailedMFAException(f"Security key assertion failed: {error}") from error
    return _to_assertion(result)


def _to_assertion(result: Any) -> WebAuthnAssertion:  # pragma: no cover - requires hardware
    return WebAuthnAssertion(
        client_data=bytes(result.response.client_data),
        authenticator_data=bytes(result.response.authenticator_data),
        signature=bytes(result.response.signature),
        user_handle=result.response.user_handle,
        credential_id=bytes(result.raw_id),
    )
