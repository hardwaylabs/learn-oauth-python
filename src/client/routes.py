"""
OAuth Client Routes

This module contains all the route handlers for the OAuth client application.
Each route demonstrates a different part of the OAuth 2.1 flow with educational logging.
"""

from fastapi import Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import httpx
from urllib.parse import urlencode, parse_qs
from typing import Optional
import secrets

from ..shared.oauth_models import TokenRequest, TokenResponse
from ..shared.crypto_utils import PKCEGenerator
from ..shared.logging_utils import OAuthLogger

# This will be imported and used by main.py
# Routes will be added to the main app instance