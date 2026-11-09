"""CLI for agent-crypto-identity-attestor."""
import sys
import argparse
from .attestor import CryptoIdentityAttestor


def main():
    parser = argparse.ArgumentParser(description="Agent Crypto Identity Attestor CLI")
    parser.add_argument("--demo", action="store_true", help="Run cryptographic token issuance and verification demo")
    args = parser.parse_args()

    if args.demo:
        attestor = CryptoIdentityAttestor(master_secret="antigravity_secret_2026")
        token = attestor.issue_token("worker_agent_42", roles=["database_read", "exec_tool"], ttl_seconds=60)
        print("Issued Delegation Token:")
        print(f"  {token}")

        check = attestor.verify_token(token, required_role="database_read")
        print(f"Verification: Valid={check.is_valid} | Agent={check.payload.get('sub')}")

        attestor.revoke_token(token)
        revoked_check = attestor.verify_token(token)
        print(f"Post-Revocation: Valid={revoked_check.is_valid} | Error={revoked_check.error}")
    else:
        parser.print_help()
    sys.exit(0)


if __name__ == "__main__":
    main()
