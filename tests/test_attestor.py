"""Unit tests for agent-crypto-identity-attestor."""
import unittest
import time
from agent_crypto_identity_attestor.attestor import CryptoIdentityAttestor


class TestCryptoIdentityAttestor(unittest.TestCase):
    def setUp(self):
        self.attestor = CryptoIdentityAttestor(master_secret="test_secret_key_123")

    def test_valid_token(self):
        token = self.attestor.issue_token("subagent_1", ["write_file", "read_file"], ttl_seconds=10)
        res = self.attestor.verify_token(token, "write_file")
        self.assertTrue(res.is_valid)
        self.assertEqual(res.payload["sub"], "subagent_1")

    def test_missing_role(self):
        token = self.attestor.issue_token("subagent_1", ["read_file"], ttl_seconds=10)
        res = self.attestor.verify_token(token, "admin_drop")
        self.assertFalse(res.is_valid)
        self.assertIn("Missing required role", res.error)

    def test_revocation(self):
        token = self.attestor.issue_token("subagent_1", ["read_file"], ttl_seconds=10)
        self.attestor.revoke_token(token)
        res = self.attestor.verify_token(token)
        self.assertFalse(res.is_valid)
        self.assertIn("revoked", res.error)
