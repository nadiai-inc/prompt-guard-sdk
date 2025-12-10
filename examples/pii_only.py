"""
NadiAI Prompt Guard - PII-Only Detection Example
=================================================
Demonstrates using only PII detection (no ML models required).
This mode is useful when you only need regex-based detection
and don't want to download the ML models.
"""

from nadiai_prompt_guard import PromptGuard

# Create scanner with only PII detection enabled
# No ML models will be loaded, so no download required!
guard = PromptGuard(
    auto_load=False,  # Don't load ML models
    enable_injection=False,
    enable_harmful=False,
    enable_pii=True
)

# Test cases with various PII types
test_cases = [
    # Social Security Numbers
    ("SSN Format", "My social security number is 123-45-6789"),

    # Credit Cards
    ("Credit Card", "Pay with card 4532-1234-5678-9012"),
    ("Credit Card No Dash", "Card number 4532123456789012"),

    # Email Addresses
    ("Email", "Contact me at john.smith@company.com"),

    # Phone Numbers
    ("Phone", "Call me at 555-123-4567"),
    ("Phone Alt", "My number is (555) 123-4567"),

    # AWS Keys
    ("AWS Key", "AWS Access Key: AKIAIOSFODNN7EXAMPLE"),

    # Passwords in code
    ("Password", 'password = "mysecretpassword123"'),
    ("Passwd", "passwd: supersecret"),

    # API Keys
    ("API Key", "api_key: sk-1234567890abcdef1234567890"),

    # IP Addresses
    ("IP Address", "Server IP: 192.168.1.100"),

    # Safe content (should not trigger)
    ("Safe", "What is the weather like today?"),
    ("Safe Numbers", "The year is 2024 and I have 3 cats"),
]

print("=" * 70)
print("PII DETECTION TEST (No ML Models Required)")
print("=" * 70)

for name, prompt in test_cases:
    result = guard.scan(prompt)

    status = "BLOCKED" if result.blocked else "SAFE"

    print(f"\n[{status}] {name}")
    print(f"  Input: {prompt}")

    if result.threats:
        for threat in result.threats:
            print(f"  -> {threat.type}: {threat.description}")
            if threat.matched_pattern:
                print(f"     Matched: {threat.matched_pattern}")
    else:
        print("  -> No PII detected")

print("\n" + "=" * 70)
print("PII Detection Complete")
print("=" * 70)

# Get scanner status
status = guard.get_status()
print(f"\nScanner Status:")
print(f"  ML Models Loaded: {status['loaded']}")
print(f"  Scanners Enabled: {status['scanners_enabled']}")
print(f"  ONNX Available: {status['onnx_available']}")
