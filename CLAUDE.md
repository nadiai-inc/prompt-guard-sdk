# CLAUDE.md - LLMSEC LITE SDK

> Build context for Claude Code when working on the SDK.

## What is This?

LLMSEC LITE is a lightweight Python SDK providing 6 guard rails for LLM security. It lives inside the main llmsec repo at `/sdk` but is publishable as a standalone PyPI package.

## Quick Reference

```
Package:     llmsec-lite
Location:    /sdk (this directory)
Python:      3.9+
Disk:        ~138 MB (models)
RAM Target:  ~200 MB
Latency:     ~5ms (local) / ~300ms (full)
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
├── pyproject.toml         <- Package config
├── .env.example           <- Environment template
├── llmsec_lite.config.example.json <- Config template for database integration
├── test_all_scanners.py   <- Comprehensive test script
├── src/
│   └── llmsec_lite/
│       ├── __init__.py    <- Exports TrustGuard, ScanResult, download_models
│       ├── guard.py       <- Main TrustGuard class
│       ├── router.py      <- SMART ROUTER (parallel, tiered, early exit)
│       ├── config.py      <- Configuration
│       ├── cli.py         <- CLI commands (llmsec-lite download)
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
│       │   └── config.py         <- Config schemas
│       └── utils/
│           ├── redactor.py
│           └── logger.py
├── tests/
│   ├── test_injection.py
│   ├── test_toxicity.py
│   ├── test_secrets.py
│   ├── test_pii.py
│   ├── test_code_injection.py
│   └── conftest.py
└── examples/
```

## Model Registry

Located in `src/llmsec_lite/models/downloader.py`:

```python
MODEL_REGISTRY = {
    "injection": {
        "filename": "injection_model.onnx",
        "url": "https://huggingface.co/testsavantai/prompt-injection-defender-small-v0-onnx/resolve/main/model.onnx",
        "size_mb": 115,
        "description": "Small BERT prompt injection detector",
    },
    "toxicity": {
        "filename": "toxic_model.onnx",
        "url": "https://huggingface.co/minuva/MiniLMv2-toxic-jigsaw-onnx/resolve/main/model_optimized_quantized.onnx",
        "size_mb": 23,
        "description": "MiniLMv2 toxic comment classifier",
    },
    "tokenizer": {
        "filename": "tokenizer.json",
        "url": "https://huggingface.co/testsavantai/prompt-injection-defender-small-v0-onnx/resolve/main/tokenizer.json",
        "size_mb": 1,
    },
    "toxicity_tokenizer": {
        "filename": "toxicity_tokenizer.json",
        "url": "https://huggingface.co/minuva/MiniLMv2-toxic-jigsaw-onnx/resolve/main/tokenizer.json",
        "size_mb": 1,
    },
}
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

### Early Exit Conditions
- injection: Score > 0.9
- secrets: API key or password found
- pii: SSN or credit card found
- toxicity: Score > 0.9
- code_injection: DROP/DELETE or shell command

## Key Commands

```bash
# Install in dev mode
pip install -e ".[dev]"

# Run tests
pytest tests/

# Run comprehensive scanner test
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

## Configuration Methods

### 1. JSON Configuration (Recommended for Database Integration)

The SDK supports JSON-based configuration for easy database storage/retrieval:

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

# Save config template
TrustGuard.save_config_template("llmsec_lite.config.json")
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

### 2. Environment Variables (Legacy)

```bash
# API Keys
OPENAI_API_KEY=sk-...          # OpenAI for hallucination
LLMSEC_API_KEY=sk-...          # Alternative

# LLM Configuration
TRUSTGUARD_LLM=gpt-4o-mini     # Model for hallucination judge

# SDK Configuration
LLMSEC_MODE=local              # local | full
LLMSEC_SENSITIVITY=balanced    # low | balanced | strict
LLMSEC_CACHE_DIR=~/.llmsec-lite

# Scanner Toggles
LLMSEC_ENABLE_INJECTION=true
LLMSEC_ENABLE_TOXICITY=true
LLMSEC_ENABLE_SECRETS=true
LLMSEC_ENABLE_PII=true
LLMSEC_ENABLE_CODE_INJECTION=true
LLMSEC_ENABLE_HALLUCINATION=true

# PII Settings
LLMSEC_PII_REDACTION=true
LLMSEC_PII_REDACTION_STYLE=full  # full, partial, hash
```

## Test Results

### Complex Prompt Injection Tests (Small Model 115 MB)

| Test Category | Result |
|---------------|--------|
| Basic attacks (ignore instructions) | 100% |
| Obfuscation (Base64, Leetspeak, Unicode) | 100% |
| Role-playing attacks | 67% |
| Jailbreaks (DAN, Developer mode) | 100% |
| Context manipulation (nested, markdown, JSON) | 100% |
| Multi-step attacks | 100% |
| Clean text (no false positives) | 100% |
| **Overall** | **87%** |

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
8. **Tests**: For every scanner
