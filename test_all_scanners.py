#!/usr/bin/env python3
"""Comprehensive test of LLMSEC LITE scanners (secrets + PII)."""

import asyncio
import time
from dotenv import load_dotenv

# Load .env file
load_dotenv()

from llmsec_lite import TrustGuard
from llmsec_lite.scanners.secrets import SecretsScanner
from llmsec_lite.scanners.pii import PIIScanner


def print_header(title: str):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def print_result(name: str, detected: bool, score: float, latency: float, findings: list):
    status = "✅ DETECTED" if detected else "❌ NOT DETECTED"
    print(f"\n  Test: {name}")
    print(f"  Result: {status}")
    print(f"  Score: {score:.2f}")
    print(f"  Latency: {latency:.1f}ms")
    if findings:
        for f in findings[:3]:  # Show first 3 findings
            print(f"  Finding: [{f.severity.value}] {f.type}: {f.value[:50]}...")


async def test_secrets_scanner():
    print_header("1. SECRETS SCANNER")
    scanner = SecretsScanner()

    test_cases = [
        ("AWS Access Key", "My key is AKIAIOSFODNN7EXAMPLE", True),
        ("OpenAI API Key", "Use sk-1234567890abcdef1234567890abcdef1234567890abcdef", True),
        ("GitHub Token", "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", True),
        ("Generic Password", "password = MySecretPass123!", True),
        ("MongoDB URI", "mongodb://admin:pass123@localhost:27017/db", True),
        ("JWT Token", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", True),
        ("Clean text", "This is a normal message with no secrets.", False),
    ]

    passed = 0
    for name, text, should_detect in test_cases:
        start = time.perf_counter()
        result = await scanner.scan(text)
        latency = (time.perf_counter() - start) * 1000

        detected = result.score > 0.3
        correct = detected == should_detect
        if correct:
            passed += 1

        print_result(name, detected, result.score, latency, result.findings)

    print(f"\n  Summary: {passed}/{len(test_cases)} tests passed")
    return passed, len(test_cases)


async def test_pii_scanner():
    print_header("2. PII SCANNER")
    scanner = PIIScanner()

    test_cases = [
        ("SSN", "My SSN is 123-45-6789", True),
        ("Credit Card (Visa)", "Card: 4111111111111111", True),
        ("Email", "Contact: john.doe@example.com", True),
        ("Phone", "Call me at 555-123-4567", True),
        ("IP Address", "Server IP: 192.168.1.100", True),
        ("Clean text", "Hello, how are you today?", False),
    ]

    passed = 0
    for name, text, should_detect in test_cases:
        start = time.perf_counter()
        result = await scanner.scan(text)
        latency = (time.perf_counter() - start) * 1000

        detected = result.score > 0.0
        correct = detected == should_detect
        if correct:
            passed += 1

        print_result(name, detected, result.score, latency, result.findings)

        # Show redaction
        if result.metadata.get("redacted_text") and detected:
            print(f"  Redacted: {result.metadata['redacted_text'][:60]}...")

    print(f"\n  Summary: {passed}/{len(test_cases)} tests passed")
    return passed, len(test_cases)


async def test_full_guard():
    print_header("3. FULL TRUSTGUARD INTEGRATION")

    guard = TrustGuard(mode="local")

    print(f"\n  Enabled scanners: {list(guard._scanners.keys())}")

    # Test input scanning
    print("\n  --- Input Scan Test ---")
    test_input = "My SSN is 123-45-6789 and API key is sk-test1234567890abcdef1234567890abcdef"

    start = time.perf_counter()
    result = await guard.scan_input_async(test_input)
    latency = (time.perf_counter() - start) * 1000

    print(f"  Input: {test_input[:50]}...")
    print(f"  Blocked: {result.blocked}")
    print(f"  Risk Score: {result.risk_score:.2f}")
    print(f"  Latency: {latency:.1f}ms")
    print(f"  Checks run: {list(result.checks.keys())}")
    if result.reasons:
        print(f"  Reasons: {result.reasons[:2]}")

    # Test output scanning
    print("\n  --- Output Scan Test ---")
    test_output = "The customer's email is john@example.com and SSN is 123-45-6789"

    start = time.perf_counter()
    result = await guard.scan_output_async(test_output)
    latency = (time.perf_counter() - start) * 1000

    print(f"  Output: {test_output[:50]}...")
    print(f"  Blocked: {result.blocked}")
    print(f"  Risk Score: {result.risk_score:.2f}")
    print(f"  Latency: {latency:.1f}ms")
    print(f"  Sanitized: {result.sanitized_text[:50] if result.sanitized_text else 'N/A'}...")


async def main():
    print("\n" + "=" * 60)
    print("  LLMSEC LITE - COMPREHENSIVE SCANNER TEST")
    print("=" * 60)

    total_passed = 0
    total_tests = 0

    # Test each scanner
    p, t = await test_secrets_scanner()
    total_passed += p
    total_tests += t

    p, t = await test_pii_scanner()
    total_passed += p
    total_tests += t

    await test_full_guard()

    # Final summary
    print_header("FINAL SUMMARY")
    print(f"\n  Total Tests Passed: {total_passed}/{total_tests}")
    if total_tests > 0:
        print(f"  Accuracy: {total_passed/total_tests*100:.1f}%")


if __name__ == "__main__":
    asyncio.run(main())
