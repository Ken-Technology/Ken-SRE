#!/usr/bin/python3
"""Offline known-answer checks for the pinned broker Python runtime."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsxpHHgEZ10dJFpaYHmT3
xrhk3jshR0XoMBVuIlevHpCmwIzVOy5FKjI2KMX/p2NJa7nH4hEhcDWbTkHJzddT
h5Eh1Z88TGMkOhIVFegrkLn1A9sjmLY5N6klA1vxg+3TmVC+dYi/mag0SNftfmfJ
TO5AIeBO7N2h+5oI6rsa4m4Y/W7ip9gV7pp2FRaOpvTQTV+vb6jVRvIgliKFidsL
Ll6CZquJC2+IErPR7NSvuvzcABr7VFwKf+L3hFqM6VrxuvY2dtykkGFpjW7Ha+Ar
e31Q8mQqZ/yiNfNBjvEt8be9C1cCawWJW4qMn5+Mq++vfRiyphVU2X1g/U1rhZkK
0wIDAQAB
-----END PUBLIC KEY-----
"""
TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRhc2s2LWthdCJ9.eyJpc3MiOiJrZW4tdGFzazYiLCJhdWQiOiJvZmZsaW5lLWtub3duLWFuc3dlciIsInN1YiI6InJ1bnRpbWUiLCJleHAiOjQxMDI0NDQ4MDB9.XdvivaDurE334pKEXPYJA2fGNhY_ShpZkFXdJ0GGnzGm0BmlUqycBgA6wvgQuKXVchX5fG9jqzq2WrvfjK1uDyYu9gUOrAngtfw9dGXKWhv7ET7eKS2xPpI1Gvm3-EZ2h7ixKi9Zcd8B-1-pfcPERe3Tl0WUDLN1fFG302aP3YHI3ea1357lMAreXPyZdW51ZbfB2quAGgFMNpLbZ0ofqhDEF8Sx8SUkQVbGvmMgnLMfHsccpqeDTRa0Ok3hXCVV59KV8_xySIZBSRHK8E7WPCrML1VhlR4SSPvph5KEnDxWo-P3j8Ud_z06GIh3QrrX7LFCpAUMy5EOtsTOLTlH7g"


def _origin(module, expected: str) -> None:
    if Path(module.__file__).resolve() != Path(expected):
        raise RuntimeError("module_origin_mismatch")


def yaml_duplicate_key() -> None:
    import yaml
    _origin(yaml, "/usr/lib/python3/dist-packages/yaml/__init__.py")
    class Loader(yaml.SafeLoader): pass
    def mapping(loader, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in result: raise ValueError("duplicate")
            result[key] = loader.construct_object(value_node, deep=deep)
        return result
    Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    try: yaml.load("outer:\n  key: one\n  key: two\n", Loader=Loader)
    except ValueError: return
    raise RuntimeError("duplicate_key_accepted")


def jwt_rs256() -> None:
    import jwt
    import cryptography
    _origin(jwt, "/usr/lib/python3/dist-packages/jwt/__init__.py")
    _origin(cryptography, "/usr/lib/python3/dist-packages/cryptography/__init__.py")
    claims = jwt.decode(TOKEN, PUBLIC_KEY, algorithms=["RS256"], issuer="ken-task6", audience="offline-known-answer")
    if claims != {"iss":"ken-task6","aud":"offline-known-answer","sub":"runtime","exp":4102444800}:
        raise RuntimeError("jwt_known_answer_mismatch")


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("check", choices=("yaml-duplicate-key", "jwt-rs256")); args = parser.parse_args()
    if not sys.flags.isolated: return 1
    try:
        yaml_duplicate_key() if args.check == "yaml-duplicate-key" else jwt_rs256()
        return 0
    except Exception:
        return 1


if __name__ == "__main__": raise SystemExit(main())
