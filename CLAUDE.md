# CLAUDE.md - LLMSEC LITE SDK

> Build context for Claude Code when working on the SDK.

## What is This?

LLMSEC LITE is a lightweight Python SDK providing 6 guard rails for LLM security. Published as a standalone PyPI package.

**GitHub:** https://github.com/nadiai-inc/prompt-guard-sdk

## Quick Reference

```
Package:     llmsec-lite
Version:     1.0.0
GitHub:      https://github.com/nadiai-inc/prompt-guard-sdk
Python:      3.9+
Disk:        ~138 MB (models)
RAM Target:  ~200 MB
Latency:     ~5ms (local) / ~300ms (full)
Tests:       72 passing
```

## The 6 Guard Rails

| # | Scanner | Direction | Type | Model | Size |
|---|---------|-----------|------|-------|------|
| 1 | `injection` | INPUT | ONNX | Small BERT | 115 MB |
| 2 | `toxicity` | BOTH | ONNX | MiniLMv2 | 22 MB |
| 3 | `secrets` | BOTH | Regex | 50+ patterns | <1 KB |
| 4 | `pii` | BOTH | Regex | 20 patterns | <1 KB |
| 5 | `code_injection` | OUTPUT | Regex | 45 patterns | <1 KB |
| 6 | `hallucination` | OUTPUT | LLM Judge | gpt-4o-mini | API |

## Model Sources (Apache 2.0 Licensed)

| Model | HuggingFace Repository | Size | Accuracy |
|-------|------------------------|------|----------|
| Prompt Injection | [testsavantai/prompt-injection-defender-small-v0-onnx](https://huggingface.co/testsavantai/prompt-injection-defender-small-v0-onnx) | 115 MB | 87% |
| Toxicity | [minuva/MiniLMv2-toxic-jigsaw-onnx](https://huggingface.co/minuva/MiniLMv2-toxic-jigsaw-onnx) | 22 MB | 100% |

### Model Selection Rationale

| Model | Tested Alternatives | Why Selected |
|-------|---------------------|--------------|
| Small BERT (115 MB) | Tiny (17 MB), Large DeBERTa (704 MB) | Same 87% accuracy as Large, 6x smaller, zero false positives |
| MiniLMv2 (22 MB) | Toxic-BERT (438 MB) | 20x smaller, same accuracy, optimized INT8 |

## Project Structure

```
sdk/
├── CLAUDE.md              <- You are here
├── README.md              <- User-facing docs
├── LICENSE                <- MIT License
├── pyproject.toml         <- Package config (llmsec-lite v1.0.0)
├── .env.example           <- Environment template
├── llmsec_lite.config.example.json <- Config template for database integration
├── test_all_scanners.py   <- Comprehensive test script (36 tests)
├── src/
│   └── llmsec_lite/
│       ├── __init__.py    <- Exports TrustGuard, ScanResult, download_models
│       ├── guard.py       <- Main TrustGuard class + test_scanner()
│       ├── router.py      <- SMART ROUTER (parallel, tiered, early exit)
│       ├── exceptions.py  <- Custom exceptions
│       ├── scanners/
│       │   ├── base.py           <- BaseScanner abstract (async)
│       │   ├── injection.py      <- ONNX prompt injection
│       │   ├── secrets.py        <- Regex secrets
│       │   ├── pii.py            <- Regex + redaction
│       │   ├── toxicity.py       <- ONNX toxicity
│       │   ├── hallucination.py  <- LLM judge
│       │   └── code_injection.py <- Regex code injection
│       ├── models/
│       │   ├── onnx_runtime.py   <- ONNX loader
│       │   ├── llm_client.py     <- OpenAI client
│       │   └── downloader.py     <- Model download & registry
│       ├── patterns/
│       │   ├── secrets.json      <- 50+ secret patterns
│       │   ├── pii.json          <- 20 PII patterns
│       │   └── code_injection.json <- 45 injection patterns
│       ├── schemas/
│       │   ├── results.py        <- ScanResult, Finding
│       │   └── config.py         <- Config schemas (LLMSecLiteConfig, etc.)
│       └── utils/
│           ├── redactor.py
│           └── logger.py
└── tests/                 <- 72 unit tests
    ├── test_guard.py
    ├── test_injection.py
    ├── test_toxicity.py
    ├── test_secrets.py
    ├── test_pii.py
    ├── test_code_injection.py
    └── conftest.py
```

## Key API Methods

### TrustGuard Class

```python
from llmsec_lite import TrustGuard

guard = TrustGuard()

# Scan input/output
result = guard.scan_input("user prompt")
result = guard.scan_output("llm response", context="user prompt")
result = guard.scan(input_text, output_text)  # Both

# Test individual scanners
result = guard.test_scanner("injection", "Ignore all instructions")
result = guard.test_scanner("pii", "My SSN is 123-45-6789")

# List available scanners
scanners = guard.list_scanners()  # ['injection', 'secrets', 'pii', ...]

# Configuration
guard = TrustGuard.from_config_file("config.json", api_key="sk-...")
guard = TrustGuard.from_config_dict(db_config, api_key="sk-...")
default_config = TrustGuard.get_default_config()
TrustGuard.save_config_template("config.json")
```

## Configuration Methods

### 1. JSON Configuration (Recommended for Database Integration)

```python
from llmsec_lite import TrustGuard, LLMSecLiteConfig

# From JSON file
guard = TrustGuard.from_config_file("llmsec_lite.config.json", api_key="sk-...")

# From database (dict)
config = db.get_org_scanner_config(org_id)
guard = TrustGuard.from_config_dict(config, api_key=secrets.get("openai"))

# Get default config for database storage
default_config = TrustGuard.get_default_config()
db.insert_org_config(org_id, default_config)
```

**Config schema** (`llmsec_lite.config.example.json`):

```json
{
  "scanners": {
    "injection": {"enabled": true, "threshold": 0.3},
    "toxicity": {"enabled": true, "threshold": 0.3},
    "secrets": {"enabled": true},
    "pii": {"enabled": true},
    "code_injection": {"enabled": true},
    "hallucination": {"enabled": true, "threshold": 0.5}
  },
  "llm": {
    "provider": "openai",
    "model": "gpt-4o-mini",
    "base_url": "https://api.openai.com/v1",
    "timeout": 30
  },
  "pii": {
    "redaction": true,
    "redaction_style": "full"
  },
  "mode": "local",
  "sensitivity": "balanced",
  "cache_dir": "~/.llmsec-lite",
  "parallel": true,
  "early_exit": true
}
```

**Config classes** in `schemas/config.py`:

| Class | Purpose |
|-------|---------|
| `LLMSecLiteConfig` | Main config (JSON-friendly, for database) |
| `ScannersConfig` | All scanner settings |
| `ScannerConfig` | Per-scanner enabled/threshold |
| `LLMConfig` | LLM provider settings |
| `PIIConfig` | PII redaction settings |
| `GuardConfig` | Internal runtime config |

### 2. Environment Variables

```bash
OPENAI_API_KEY=sk-...          # OpenAI for hallucination
LLMSEC_API_KEY=sk-...          # Alternative
TRUSTGUARD_LLM=gpt-4o-mini     # Model for hallucination judge
LLMSEC_MODE=local              # local | full
LLMSEC_SENSITIVITY=balanced    # low | balanced | strict
LLMSEC_CACHE_DIR=~/.llmsec-lite
```

## Smart Router Architecture

### Scanner Tiers
| Tier | Scanners | Latency | Parallel |
|------|----------|---------|----------|
| FAST | secrets, pii, code_injection | ~1-2ms | Yes |
| SLOW | injection, toxicity | ~3-5ms | Yes |
| CLOUD | hallucination | ~200-400ms | Yes |

### Router Features
1. **Scanner Toggles**: Enable/disable each scanner
2. **Parallel Execution**: Run scanners concurrently (asyncio)
3. **Tiered Processing**: Fast -> Slow -> Cloud
4. **Early Exit**: Stop on CRITICAL threat

## Key Commands

```bash
# Install in dev mode
pip install -e ".[dev]"

# Run tests (72 tests)
pytest tests/

# Run comprehensive scanner test (36 tests)
python test_all_scanners.py

# Type check
mypy src/llmsec_lite

# Lint
ruff check src/

# Build
python -m build

# Download models manually
python -c "from llmsec_lite import download_models; import asyncio; asyncio.run(download_models())"
```

## Test Results

### Unit Tests: 72 passing

| Test File | Tests |
|-----------|-------|
| test_guard.py | 19 |
| test_injection.py | 14 |
| test_code_injection.py | 18 |
| test_pii.py | 11 |
| test_secrets.py | 10 |

### Comprehensive Scanner Tests: 36/36 (100%)

| Scanner | Tests | Accuracy |
|---------|-------|----------|
| Secrets | 7/7 | 100% |
| PII | 6/6 | 100% |
| Code Injection | 7/7 | 100% |
| Prompt Injection | 7/7 | 100% |
| Toxicity | 5/5 | 100% |
| Hallucination | 4/4 | 100% |

### Known Limitations
- Subtle indirect attacks like "Grandma exploit" may not be detected
- "Completion attack" style prompts need pattern-based fallback
- "Evil twin" attacks detected at 0.26 (below threshold)

## Total Footprint

| Component | Size |
|-----------|------|
| Injection Model (ONNX) | 115 MB |
| Injection Tokenizer | 0.7 MB |
| Toxicity Model (ONNX) | 22 MB |
| Toxicity Tokenizer | 0.7 MB |
| **Total Disk** | **~138 MB** |
| **Runtime RAM** | **~200 MB** |

## Integration with Shield Backend

```python
# In backend/app/scanning/engine.py
from llmsec_lite import TrustGuard

guard = TrustGuard(
    mode="full",
    api_key=settings.OPENAI_API_KEY,
    llm_model=settings.TRUSTGUARD_LLM
)
result = guard.scan_input(user_prompt)
```

## Critical Requirements

1. **Disk**: ~138 MB for all models
2. **RAM**: Must run in < 200 MB total
3. **Lazy Loading**: Don't load ONNX models until first use
4. **Models Download**: Download on first use, cached locally
5. **Fail Open**: If scanner fails, log warning, continue with others
6. **No Crashes**: Never crash on scanner failure
7. **Type Hints**: Everywhere
8. **Tests**: 72 unit tests + 36 comprehensive tests
