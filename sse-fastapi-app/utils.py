from typing import Dict
from dotenv import load_dotenv
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi import Request, Depends
from fastapi.exceptions import HTTPException
from loguru import logger

import jwt  # This is PyJWT not jwt
import os

# This code was taken and modified from
# https://github.com/auth0-blog/auth0-python-fastapi-sample/
# blob/main/application/utils.py

load_dotenv()

token_auth_scheme = HTTPBearer()


async def authenticate_client_token(  # noqa: C901
    request: Request,
    token: HTTPAuthorizationCredentials = Depends(token_auth_scheme)
):
    """Authenticate user's JWT.

    :param request: FastAPI Request object for setting user for authentication dependency.
    :param token: Authorization token.
    :return: User details
    """
    jwks_client = request.app.state.jwks_client
    verify_token = VerifyToken(token.credentials, jwks_client)

    payload = verify_token.verify()
    logger.info(payload)
    if payload.get("status") == "error":
        raise HTTPException(status_code=403, detail=payload.get("msg"))

    request.state.user = payload
    return payload


async def authenticate_m2m_token(  # noqa: C901
    request: Request,
    token: HTTPAuthorizationCredentials = Depends(token_auth_scheme)
):
    """Authenticate user's JWT.

    :param request: FastAPI Request object for setting user for authentication dependency.
    :param token: Authorization token.
    :return: User details
    """
    jwks_client = request.app.state.jwks_client
    verify_token = VerifyToken(token.credentials, jwks_client)

    payload = verify_token.verify_m2m()
    logger.info(payload)
    if payload.get("status") == "error":
        raise HTTPException(status_code=403, detail=payload.get("msg"))

    request.state.user = payload
    return payload


class VerifyToken:
    """Does all the token verification using PyJWT."""

    def __init__(self, token, jwks_client, permissions=None, scopes=None) -> None:
        """Initializes the class.

        :param token: Authorization token.
        :param permissions: Permissions to check.
        :param scopes: Scopes to check.
        """
        self.token = token
        self.permissions = permissions
        self.scopes = scopes
        self.jwks_client = jwks_client

        self.config = {
            "API_AUDIENCE": os.getenv("API_AUDIENCE"),
            "ISSUER": os.getenv("ISSUER"),
            "ALGORITHMS": os.getenv("ALGORITHMS"),
        }
        self.m2m_config = {
            "API_AUDIENCE": os.getenv("M2M_API_AUDIENCE"),
            "ISSUER": os.getenv("M2M_ISSUER"),
            "ALGORITHMS": os.getenv("M2M_ALGORITHMS"),
        }

    def verify(self) -> Dict:  # noqa: C901 WPS212
        """Verifies the token and returns the payload.

        :return: payload of the token.
        """
        try:
            self.signing_key = self.jwks_client.get_signing_key_from_jwt(
                self.token,
            ).key
        except jwt.exceptions.PyJWKClientError as error:
            logger.error(error)
            return {"status": "error", "msg": error.__str__()}  # noqa: WPS609
        except jwt.exceptions.DecodeError as error:
            logger.error(error)
            return {"status": "error", "msg": error.__str__()}  # noqa: WPS609

        try:
            payload = jwt.decode(
                self.token,
                self.signing_key,
                algorithms=self.config["ALGORITHMS"],
                audience=self.config["API_AUDIENCE"],
                issuer=self.config["ISSUER"],
            )
        except Exception as error:
            logger.error(error)
            return {"status": "error", "message": "Invalid token."}

        if self.scopes:
            result = self._check_claims(payload, "scope", str, self.scopes.split(" "))
            if result.get("status") == "error":
                return result

        if self.permissions:
            result = self._check_claims(payload, "permissions", list, self.permissions)
            if result.get("status") == "error":
                return result

        return payload

    def verify_m2m(self) -> Dict:  # noqa: C901 WPS212
        """Verifies the m2m token and returns the payload.

        :return: payload of the token.
        """
        try:
            self.signing_key = self.jwks_client.get_signing_key_from_jwt(
                self.token,
            ).key
        except jwt.exceptions.PyJWKClientError as error:
            return {"status": "error", "msg": error.__str__()}  # noqa: WPS609
        except jwt.exceptions.DecodeError as error:
            return {"status": "error", "msg": error.__str__()}  # noqa: WPS609

        try:
            payload = jwt.decode(
                self.token,
                self.signing_key,
                algorithms=self.m2m_config["ALGORITHMS"],
                audience=self.m2m_config["API_AUDIENCE"],
                issuer=self.m2m_config["ISSUER"],
            )
        except Exception:
            return {"status": "error", "message": "Invalid token."}

        grant_type = payload["gty"]
        if grant_type != "client-credentials":
            return {"status": "error", "message": "Invalid token."}

        if self.scopes:
            result = self._check_claims(payload, "scope", str, self.scopes.split(" "))
            if result.get("status") == "error":
                return result

        if self.permissions:
            result = self._check_claims(payload, "permissions", list, self.permissions)
            if result.get("status") == "error":
                return result

        return payload

    def _check_claims(self, payload, claim_name, claim_type, expected_value) -> Dict:
        """Checks the claims in the token.

        :param payload: Payload of the token.
        :param claim_name: Name of the claim.
        :param claim_type: Type of the claim.
        :param expected_value: Expected value of the claim.
        :return: Result of the check.
        """
        instance_check = isinstance(payload[claim_name], claim_type)
        result = {"status": "success", "status_code": 200}

        payload_claim = payload[claim_name]

        if claim_name not in payload or not instance_check:
            result["status"] = "error"
            result["status_code"] = 400

            result["code"] = f"missing_{claim_name}"
            result["msg"] = f"No claim '{claim_name}' found in token."
            return result

        if claim_name == "scope":
            payload_claim = payload[claim_name].split(" ")

        for value in expected_value:
            if value not in payload_claim:
                result["status"] = "error"
                result["status_code"] = 403

                result["code"] = f"insufficient_{claim_name}"
                result["msg"] = (
                    f"Insufficient {claim_name} ({value}). You "
                    "don't have access to this resource"
                )
                return result
        return result
