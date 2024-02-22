#!/usr/bin/env python3
"""Module for User
"""


from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class User(Base):
    """A class representing a user.

    Attributes:
        __tablename__ (str): name database where
        user records are stored.
        id (int): unique identifier.
        email (str): email address.
        hashed_password (str): The of the user.
        session_id (str): The sess to maintain
        user sessions.
        reset_token (str): The reset ed for password
        resets.
    """
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)
    hashed_password = Column(String(250), nullable=False)
    session_id = Column(String(250), nullable=True)
    reset_token = Column(String(250), nullable=True)
