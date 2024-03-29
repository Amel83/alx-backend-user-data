#!/usr/bin/env python3
"""Authenticating model.
"""
from flask import request
from typing import List, TypeVar
import fnmatch


class Auth:
    """Authenticating cls
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ method to check
        """
        if path is None:
            return True

        if excluded_paths is None or not excluded_paths:
            return True

        for excluded_path in excluded_paths:
            if fnmatch.fnmatch(path, excluded_path):
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """ method get authorizing header.
        """
        if request is not None:
            return request.headers.get('Authorization', None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ method to get user
        """
        return None
