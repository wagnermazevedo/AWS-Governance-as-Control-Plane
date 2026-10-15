"""Criação de sessões e clientes AWS."""

import os
from typing import Optional

import boto3
from botocore.config import Config

_RETRY = Config(retries={"max_attempts": 10, "mode": "adaptive"})


def session(profile: Optional[str] = None, region: Optional[str] = None) -> boto3.Session:
    profile = profile or os.getenv("AWS_PROFILE") or None
    region = region or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1"
    return boto3.Session(profile_name=profile, region_name=region)


def client(sess: boto3.Session, service: str):
    # AWS Organizations é um serviço global com endpoint em us-east-1.
    region = "us-east-1" if service == "organizations" else sess.region_name
    return sess.client(service, region_name=region, config=_RETRY)
