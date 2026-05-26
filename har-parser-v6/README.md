# HAR Parser For Conversational AI

> A professional CLI-based digital forensics tool for analyzing HAR (HTTP Archive) files captured during interactions with conversational AI platforms.

---

## Supported Platforms

| Platform | Detection | Parsing |
|----------|-----------|---------|
| **ChatGPT** (OpenAI) | ✓ | Full |
| **Claude** (Anthropic) | ✓ | Full |
| **Gemini** (Google) | ✓ | Full |

---

## Forensic Sections

| Section | Code | Description |
|---------|------|-------------|
| Identity | 2A | User IDs, session IDs, device fingerprints, timestamps |
| Prompts | 2B | User prompts, AI responses, model versions, generation timing |
| Security | 2C | Auth tokens, cookies, security telemetry, feature flags |
| Autonomous | 2D | SSE streams, background polling, telemetry, autonomous AI actions |

---

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/har-parser-for-conversational-ai.git
cd har-parser-for-conversational-ai

# Install dependencies (Python 3.9+ required)
pip install -r requirements.txt
```

---

## Usage

### Analyze a HAR file

```bash
python main.py analyze session.har
```

### Verbose mode (shows forensic rationale for each artifact)

```bash
python main.py analyze session.har --verbose
```

### Export results

```bash
# Export as JSON
python main.py analyze session.har --export json

# Export as CSV (one file per section)
python main.py analyze session.har --export csv

# Export as Markdown report
python main.py analyze session.har --export md

# Export as plain-text report
python main.py analyze session.har --export txt

# Export all formats at once
python main.py analyze session.har --export all

# Specify output directory
python main.py analyze session.har --export all --output /tmp/forensics/
```

### Validate a HAR file

```bash
python main.py validate session.har
```

### Show forensic statistics

```bash
python main.py stats session.har
```

### Batch processing

```bash
# Process all .har files recursively in a directory
python main.py batch ./har_files/

# Batch with export
python main.py batch ./har_files/ --export json --output /tmp/results/
```

---

## CLI Output Example

```
[+] Loading HAR file: session.har
[✓] HAR loaded — 312 network entries found
[+] Validating HAR structure...
[✓] HAR structure valid
[+] Detecting conversational AI platform...
[⚡] Platform detected: CLAUDE  [ChatGPT=0 Gemini=0 Claude=480]

  Platform Detection → Claude
  ChatGPT  ░░░░░░░░░░░░░░░░░░░░  0pts
  Gemini   ░░░░░░░░░░░░░░░░░░░░  0pts
  Claude   ████████████████████  480pts

[+] Extracting SSE streams and network artifacts...
[+] Building forensic artifact inventory...
[+] Running attribution analysis (Human / AI / Platform)...
[✓] Forensic artifacts extracted: 38

══  FORENSIC SUMMARY  ══
  Platform Detected : Claude (Anthropic)
  Total Artifacts   : 38
  🧑 Human          : 14
  🤖 AI             : 11
  🏛 Platform       : 13
```

---

## Project Structure

```
har-parser-for-conversational-ai/
│
├── main.py                 # CLI entry point
├── requirements.txt
├── README.md
├── .gitignore
│
├── parsers/
│   ├── __init__.py
│   ├── loader.py           # HAR file loading
│   ├── detection.py        # Platform detection (score-based)
│   ├── helpers.py          # Shared extraction utilities
│   ├── chatgpt.py          # ChatGPT forensic pipeline
│   ├── gemini.py           # Gemini forensic pipeline
│   ├── claude.py           # Claude forensic pipeline
│   └── router.py           # Platform → parser routing
│
├── core/
│   ├── __init__.py
│   └── logger.py           # Structured logging → logs/app.log
│
├── cli/
│   ├── __init__.py
│   ├── banner.py           # ASCII banner & branding
│   └── display.py          # Rich terminal output functions
│
├── utils/
│   ├── __init__.py
│   └── export.py           # JSON / CSV / Markdown / TXT exports
│
├── exports/                # Default export output directory
├── reports/                # Report output directory
└── logs/                   # app.log lives here
```

---

## How to Capture a HAR File

1. Open your browser's Developer Tools (F12)
2. Go to the **Network** tab
3. Enable **Preserve Log**
4. Start a conversation with ChatGPT / Claude / Gemini
5. Right-click any request → **Save all as HAR with content**
6. Run the tool on the saved `.har` file

---

## Artifact Attribution

Every extracted artifact is tagged with one of three attribution labels:

| Label | Meaning |
|-------|---------|
| `HUMAN` | Originated from the user's actions or content |
| `AI` | Originated from or directly characterizes the AI model |
| `PLATFORM` | Infrastructure, session management, or telemetry |

---

## Export Formats

| Format | Extension | Description |
|--------|-----------|-------------|
| JSON | `.json` | Structured forensic report with metadata |
| CSV | `.csv` | One file per section, importable into Excel |
| Markdown | `.md` | Human-readable report with tables |
| TXT | `.txt` | Plain-text forensic report |

---

## Troubleshooting

**"Not a valid HAR file"**
: The file is missing `log.entries`. Re-export from DevTools.

**"Platform could not be identified"**
: The HAR may not contain conversational AI traffic. Verify you captured the correct session.

**"No .har files found"**
: Ensure the directory path is correct and files have the `.har` extension.

**Import errors**
: Run `pip install -r requirements.txt` to install dependencies.

---

## License

MIT License. See `LICENSE` for details.
