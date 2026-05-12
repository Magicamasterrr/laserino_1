#!/usr/bin/env python3
"""Laserino-1: operator-side tooling for TheDivineNFT sanctified lanes and pulse telemetry."""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import hashlib
import hmac
import json
import logging
import os
import queue
import random
import secrets
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Deque, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, TypeVar

try:
    from eth_abi import encode as eth_abi_encode  # type: ignore
except Exception:  # pragma: no cover
    eth_abi_encode = None

try:
    from eth_account import Account
    from eth_account.messages import encode_defunct
except Exception:  # pragma: no cover
    Account = None
    encode_defunct = None

try:
    from web3 import Web3
except Exception:  # pragma: no cover
    Web3 = None

T = TypeVar("T")
LOG = logging.getLogger("laserino_1")


def keccak256(data: bytes) -> bytes:
    try:
        from Crypto.Hash import keccak

        k = keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()
    except Exception:
        try:
            import sha3  # type: ignore

            k = sha3.keccak_256()
            k.update(data)
            return k.digest()
        except Exception:
            raise RuntimeError(
                "keccak256 requires pycryptodome or pysha3; pip install pycryptodome"
            ) from None


def pad32(b: bytes) -> bytes:
    return b.rjust(32, b"\x00")[-32:]


def addr_to_bytes(addr: str) -> bytes:
    hx = addr.lower().removeprefix("0x")
    if len(hx) != 40:
        raise ValueError("address length")
    return bytes.fromhex(hx)


def u256_bytes(x: int) -> bytes:
    if x < 0 or x >= 1 << 256:
        raise ValueError("u256 range")
    return x.to_bytes(32, "big")


def encode_divine_order_struct(
    order_typehash: bytes,
    token_id: int,
    price_wei: int,
    nonce: int,
    deadline: int,
    buyer: str,
) -> bytes:
    if eth_abi_encode is None:
        raise RuntimeError("eth_abi is required for precise struct hashing; pip install eth_abi")
    if Web3 is None:
        buyer_a = buyer
    else:
        buyer_a = Web3.to_checksum_address(buyer)
    payload = eth_abi_encode(
        ["bytes32", "uint256", "uint256", "uint256", "uint256", "address"],
        [order_typehash, token_id, price_wei, nonce, deadline, buyer_a],
    )
    return keccak256(payload)


