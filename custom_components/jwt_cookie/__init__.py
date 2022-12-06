import gc
import jwt
import logging
from http import HTTPStatus
from os import path
from typing import Union
from multidict import MultiDictProxy
from yarl import URL
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key

import voluptuous as vol

from aiohttp import web
from homeassistant.components.http.view import HomeAssistantView

from homeassistant.helpers import config_validation as cv
from homeassistant.auth.models import User
from homeassistant.auth.const import ACCESS_TOKEN_EXPIRATION
from homeassistant.util import dt
from homeassistant.data_entry_flow import FlowResultType, FlowResult
from homeassistant.components.auth import (
    DOMAIN as AUTH_DOMAIN,
    RetrieveResultType,
    TokenView,
)
from homeassistant.components.auth.login_flow import LoginFlowResourceView
from homeassistant.core import HomeAssistant


DOMAIN = "jwt_cookie"
_LOGGER = logging.getLogger(__name__)
CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                vol.Optional("cookie_name", default="jwt_access_token"): cv.string,
                vol.Optional("audience", default="homeassistant"): cv.string,
                vol.Optional("issuer", default="homeassistant"): cv.string,
                vol.Optional("http_only", default=True): cv.boolean,
                vol.Optional("secure", default=True): cv.boolean,
                vol.Optional("domain"): cv.string,
                vol.Optional("public_key_file"): cv.path,
                vol.Optional("private_key_file"): cv.path,
            }
        )
    },
    extra=vol.ALLOW_EXTRA,
)


async def async_setup(hass: HomeAssistant, config):
    """Load configuration and register custom views"""
    domain_config = config[DOMAIN]

    # Because we start after auth, we have access to store_result
    store_result = hass.data[AUTH_DOMAIN]
    retrieve_auth = next(
        filter(lambda obj: isinstance(obj, TokenView), gc.get_objects())
    )._retrieve_auth

    # Remove old Views
    for route in hass.http.app.router._resources:
        if route.canonical == "/auth/login_flow/{flow_id}":
            _LOGGER.debug("Removed original login_flow route")
            hass.http.app.router._resources.remove(route)
        elif route.canonical == "/auth/token":
            _LOGGER.debug("Removed original token route")
            hass.http.app.router._resources.remove(route)

    private_key_path = domain_config.get("private_key_file", None)
    if private_key_path and path.isfile(private_key_path):
        _LOGGER.debug(f"Loading signing key from {private_key_path}")
        with open(private_key_path, "rb") as pem_file:
            private_key = load_pem_private_key(pem_file.read(), password=None)
    else:
        _LOGGER.debug("Generating signing key")
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    public_key = private_key.public_key()

    domain_config["private_key"] = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    domain_config["public_key"] = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    public_key_path_default = path.join(hass.config.config_dir, "jwt_cookie.pem")
    public_key_path = domain_config.get("public_key_file", public_key_path_default)

    with open(public_key_path, "wb") as pem_file:
        pem_file.write(domain_config["public_key"])

    if private_key_path:
        with open(private_key_path, "wb") as pem_file:
            pem_file.write(domain_config["private_key"])

    _LOGGER.debug("Add new routes")
    hass.http.register_view(
        JWTCookieLoginFlowResourceView(
            hass.auth.login_flow, store_result, domain_config
        )
    )
    hass.http.register_view(JWTCookieTokenView(retrieve_auth, domain_config))
    hass.http.register_view(JWTCookieRedirectView)

    return True


def create_jwt_cookie(response: web.Response, user: User, config):
    """Create a new JWT Cookie and append it to the response"""
    now = dt.utcnow()
    token = jwt.encode(
        {
            "sub": user.id,
            "name": user.name,
            "roles": [
                *(["admin"] if user.is_admin else []),
                "user",
            ],
            "aud": [config["audience"]],
            "iss": config["issuer"],
            "exp": now + ACCESS_TOKEN_EXPIRATION,
            "iat": now,
        },
        config["private_key"],
        algorithm="ES256",
    )

    response.set_cookie(
        config["cookie_name"],
        token,
        httponly=config["http_only"],
        max_age=ACCESS_TOKEN_EXPIRATION.total_seconds(),
        secure=config["secure"],
        domain=config.get("domain"),
    )


class JWTCookieRedirectView(HomeAssistantView):
    """Helper view for redirecting after oauth2"""

    url = "/auth/jwt_cookie"
    name = "api:auth:redirect"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        """Redirect based on query parameters"""

        if "state" in request.query and "code" in request.query:
            url = URL.build(
                scheme=request.url.scheme,
                authority=request.url.authority,
                path="/auth/jwt_cookie",
            )
            return web.HTTPTemporaryRedirect(request.query.getone("state"))

        if "redirect_url" in request.query:
            return_url = URL.build(
                scheme=request.url.scheme,
                authority=request.url.authority,
                path="/auth/jwt_cookie",
            )
            url = URL.build(
                scheme=request.url.scheme,
                authority=request.url.authority,
                path="/auth/authorize",
            ).with_query(
                redirect_uri=str(return_url),
                state=request.query.getone("redirect_url"),
                client_id=str(
                    URL.build(
                        scheme=request.url.scheme, authority=request.url.authority
                    )
                ),
            )
            return web.HTTPTemporaryRedirect(url)

        return self.json(
            {
                "error": "invalid_request",
                "error_description": "either redirect_url or state and code is required",
            },
            status_code=HTTPStatus.BAD_REQUEST,
        )


class JWTCookieLoginFlowResourceView(LoginFlowResourceView):
    """Wrapper around LoginFlowResourceView to create a JWT Cookie after successful login"""

    def __init__(self, flow_mgr, store_result, config) -> None:
        super().__init__(flow_mgr, store_result)
        self.config = config

    async def _async_flow_result_to_response(
        self,
        request: web.Request,
        client_id: str,
        result: FlowResult,
    ) -> web.Response:
        response = await super()._async_flow_result_to_response(
            request, client_id, dict(result)
        )

        if result["type"] == FlowResultType.CREATE_ENTRY and response.status == 200:
            hass: HomeAssistant = request.app["hass"]
            user = await hass.auth.async_get_user_by_credentials(result.pop("result"))

            if user is not None:
                create_jwt_cookie(response, user, self.config)

        return response


class JWTCookieTokenView(TokenView):
    """Wrapper around TokenView to create a JWT Cookie after refreshing a token"""

    def __init__(self, retrieve_auth: RetrieveResultType, config) -> None:
        super().__init__(retrieve_auth)
        self.config = config

    async def _async_handle_refresh_token(
        self,
        hass: HomeAssistant,
        data: MultiDictProxy[str],
        remote_addr: Union[str, None],
    ) -> web.Response:
        response = await super()._async_handle_refresh_token(hass, data, remote_addr)

        if response.status == 200:
            token = await hass.auth.async_get_refresh_token_by_token(
                data.get("refresh_token")
            )
            create_jwt_cookie(response, token.user, self.config)

        return response
