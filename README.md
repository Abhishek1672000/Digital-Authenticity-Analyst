# Digital Authenticity & AI Detection Analyst

> Multi-modal forensic authenticity checker for images, audio, PDFs, text/email, and social profiles.

## Project Structure

```
digital-authenticity-analyst/
├── src/
│   ├── core/
│   │   ├── schemas.py          # Pydantic models (EngineResult, VerdictResult, AnalysisReport)
│   │   ├── settings.py         # Environment settings (API keys, limits)
│   │   ├── intake.py           # Media type router (magic bytes + MIME + extension)
│   │   └── verdict_engine.py   # Evidence aggregator & verdict classifier
│   ├── engines/
│   │   ├── image_engine.py     # ELA, EXIF, Hive/Sightengine AI detection
│   │   ├── audio_engine.py     # Librosa splice detection, Resemblyzer speaker consistency
│   │   ├── pdf_engine.py       # PyMuPDF revision history, pyhanko signatures, font analysis
│   │   ├── text_engine.py      # Email header parsing, WHOIS, factual claim extraction
│   │   └── osint_engine.py     # WHOIS, VirusTotal, Google Vision reverse image search
│   ├── report/
│   │   └── generator.py        # Markdown / JSON report renderer
│   └── api/
│       └── app.py              # FastAPI REST API
├── tests/
│   └── unit/
│       ├── test_intake.py
│       └── test_verdict_engine.py
├── pyproject.toml
└── .env.example
```

## Quick Start

### 1. Install dependencies

```bash
pip install -e ".[dev]"
```

### 2. Configure API keys

```bash
cp .env.example .env
# Fill in your API keys in .env
```

### 3. Run the API server

```bash
uvicorn src.api.app:app --reload --port 8000
```

### 4. Analyze a file

```bash
# Image
curl -X POST http://localhost:8000/analyze \
  -F "file=@suspicious_photo.jpg" \
  -F "context=Received via WhatsApp claiming to be a news photo"

# Text / Email
curl -X POST http://localhost:8000/analyze \
  -F "text=From: support@paypa1.com..." \
  -F "output_format=json"

# URL / Social Profile
curl -X POST http://localhost:8000/analyze \
  -F "url=https://x.com/suspicious_account" \
  -F "context=Account claiming to be a government official"
```

### 5. Run tests

```bash
pytest tests/ -v
```

## API Keys Required

| Provider | Purpose | Env Var |
|---|---|---|
| Hive Moderation | AI image generation detection | `HIVE_API_KEY` |
| Sightengine | Secondary AI image detection | `SIGHTENGINE_USER` + `SIGHTENGINE_SECRET` |
| SerpAPI | Phrase origin / reverse image web search | `SERPAPI_KEY` |
| Google Vision | Profile photo reverse image search | `GOOGLE_VISION_API_KEY` |
| VirusTotal | Domain reputation | `VIRUSTOTAL_API_KEY` |
| Gemini / Anthropic | LLM claim extraction & reasoning | `GEMINI_API_KEY` / `ANTHROPIC_API_KEY` |

> All API keys are optional — the system degrades gracefully and lists skipped checks in the report.

## Design Principles

- **Never fakes tool use** — unrun checks are explicitly listed in every report
- **Text style ≠ AI** — style-based AI classification is permanently skipped per Golden Rule
- **Metadata absence ≠ forgery** — always listed as an innocent alternative
- **Confidence capping** — max High confidence only with ≥5 corroborating signals
- **Sandboxed file processing** — files processed in-process with no execution
