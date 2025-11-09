# Kokoro TTS Converter - Project Overview

## Project Type & Purpose

**Type:** Python-based Text-to-Speech (TTS) CLI Tool + Backend Learning Resource Repository

This is a **dual-purpose learning project**:

1. **Primary Application:** An interactive command-line tool that converts text files to high-quality audio using the Kokoro-82M text-to-speech model
2. **Learning Resource:** A comprehensive collection of architectural and design pattern documentation comparing PHP and Go approaches to backend development

The main utility (`tts_converter.py`) is a feature-rich interactive CLI application for local text-to-speech conversion, while the repository also contains extensive educational documentation on software design patterns, architecture, and conventions.

---

## High-Level Architecture & Code Organization

### Main Application Structure

The project is organized around a single primary application with supporting documentation:

```
tts_sk/
├── tts_converter.py              # Main TTS application (441 lines)
├── README.md                      # Application documentation
├── CLAUDE.md                      # This file (project overview)
├── requirements.txt               # Python dependencies
├── sample_text.txt               # Example test file
│
├── [Generated Assets]
├── An_Audio_Guide.wav            # Sample output (120MB)
├── An_Audio_Guide.txt            # Sample source
│
├── [Learning Documentation] (9 files, ~12K lines total)
├── naming-conventions-php-vs-go.md
├── backend-design-patterns-php-vs-go.md
├── microservices-patterns-php-vs-go.md
├── cross-cutting-patterns-php-vs-go.md
├── system-architecture-patterns-php-vs-go.md
├── testing-patterns-php-vs-go.md
├── data-persistence-patterns-sql-vs-nosql.md
├── domain-driven-design-guide.md
│
└── [Environment & Cache]
    ├── .venv/                    # Python virtual environment
    ├── __pycache__/              # Python bytecode cache
    ├── .mypy_cache/              # Type checking cache
    └── .gitignore                # Ignore patterns for git
```

### Application Architecture

The TTS converter follows an **Object-Oriented, Class-Based Design Pattern** with clear separation of concerns:

#### Core Class: `TTSConverter`

- **Responsibility:** Orchestrate the entire TTS conversion workflow
- **Dependencies:** Kokoro TTS model, Rich CLI library, Inquirer for interactive prompts
- **Key Methods:**
  - `__init__()` - Initialize converter and load configuration
  - `display_welcome()` - Show welcome banner
  - `select_input_file()` - Interactive file selection
  - `select_voice()` - Voice choice with visual table display
  - `select_speed()` - Speed selection with custom input support
  - `select_output_format()` - Format selection (WAV/MP3/OGG)
  - `select_output_path()` - Output file path confirmation
  - `read_text_file()` - Read and preview text input
  - `initialize_pipeline()` - Lazy-load TTS model
  - `convert_text_to_speech()` - Core TTS conversion with progress tracking
  - `save_audio()` - Serialize audio to disk with format conversion
  - `run()` - Main interactive workflow loop

#### Configuration Management

- Persists user preferences to `~/.kokoro_tts_config.json`
- Remembers last chosen: voice, speed, output format
- Enables faster workflows on repeat uses

#### Platform-Specific Handling

- **macOS Apple Silicon (ARM64):** Auto-detects and enables MPS fallback mode
- **Linux/Windows:** Works with installed espeak-ng

---

## Key Technologies & Frameworks

### TTS Core
- **Kokoro-82M Model** (PyTorch-based)
  - 82 million parameters
  - StyleTTS 2 + ISTFTNet architecture
  - Apache-2.0 licensed
  - Runs locally (no API keys required)
  - 24kHz mono audio output

### Python Libraries

#### Audio Processing
- **kokoro** (>=0.9.4) - Main TTS model wrapper
- **soundfile** (>=0.12.1) - WAV file I/O
- **pydub** (>=0.25.1) - Audio format conversion (MP3, OGG)
- **numpy** - Audio data manipulation

#### CLI & User Experience
- **rich** (>=13.7.0) - Terminal formatting, panels, tables, progress bars
- **inquirer** (>=3.1.3) - Interactive CLI prompts with arrow-key selection
- **tqdm** (>=4.66.1) - Progress tracking

#### External Dependencies
- **espeak-ng** - System dependency for phoneme generation
  - macOS: Install via `brew install espeak-ng`
  - Linux: Install via `apt-get install espeak-ng`
  - Windows: Download from GitHub releases

### Python Version
- **Minimum:** Python 3.9+

---

## Build/Test/Development Commands

### Setup & Installation

```bash
# 1. Clone or download the repository
cd /path/to/tts_sk

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # macOS/Linux
# or
.venv\Scripts\activate     # Windows

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Install system dependency (espeak-ng)
# macOS
brew install espeak-ng

# Linux (Ubuntu/Debian)
sudo apt-get update && sudo apt-get install espeak-ng

# Windows
# Download and install from: https://github.com/espeak-ng/espeak-ng/releases

# 5. (Optional) Make script executable on macOS/Linux
chmod +x tts_converter.py
```

### Running the Application

```bash
# Basic usage - interactive mode
python tts_converter.py

# The tool guides users through 6 steps:
# 1. Select input text file
# 2. Choose voice (20 options)
# 3. Set playback speed (0.5x - 2.0x)
# 4. Select output format (WAV/MP3/OGG)
# 5. Confirm output path
# 6. Convert and save
```

### Available Voices (20 Total)

**Female Voices (11):**
- af_heart, af_alloy, af_aoede, af_bella, af_jessica, af_kore, af_nicole, af_nova, af_river, af_sarah, af_sky

**Male Voices (9):**
- am_adam, am_echo, am_eric, am_fenrir, am_liam, am_michael, am_onyx, am_puck, am_santa

### Output Formats

- **WAV** - Uncompressed, best quality, larger file size
- **MP3** - Compressed at 192kbps, good quality, smaller size
- **OGG** - Compressed with libvorbis, open format

### Speed Options

- 0.5x (very slow)
- 0.75x (slow)
- 1.0x (normal - default)
- 1.25x (slightly faster)
- 1.5x (fast)
- 2.0x (very fast)
- Custom (0.5 - 2.0 range)

### Testing/Validation

```bash
# Test with sample file
python tts_converter.py
# When prompted, use: sample_text.txt

# Type checking (if mypy installed)
mypy tts_converter.py
```

### No Build/Compilation Required
This is a pure Python application - no compilation step needed. It runs as an interpreted script.

---

## Existing Documentation Files

### Main Documentation

1. **README.md** (226 lines)
   - Installation instructions for all platforms
   - Feature overview
   - Voice descriptions and selection guide
   - Speed options and output formats
   - Troubleshooting guide
   - Technical details about Kokoro-82M model
   - Credits and support links

### Learning Resource Documentation (PHP vs. Go Comparison Series)

2. **naming-conventions-php-vs-go.md** (857 lines)
   - Naming conventions and class role patterns
   - Coordination & control patterns
   - Data access patterns
   - Business logic naming
   - Request/response patterns
   - Language-specific idioms
   - Anti-patterns to avoid

3. **backend-design-patterns-php-vs-go.md** (1,271 lines)
   - Backend design patterns comparison
   - Gang of Four patterns in PHP vs Go
   - Creational patterns (Factory, Singleton, Builder)
   - Structural patterns (Decorator, Adapter, Proxy)
   - Behavioral patterns (Observer, Strategy, Command)

4. **microservices-patterns-php-vs-go.md** (2,915 lines)
   - Microservices architecture patterns
   - CQRS (Command Query Responsibility Segregation)
   - Event Sourcing
   - Saga pattern for distributed transactions
   - API composition and routing
   - Service discovery patterns
   - Load balancing strategies

5. **cross-cutting-patterns-php-vs-go.md** (3,698 lines)
   - Security patterns (authentication, authorization, encryption)
   - API design patterns
   - Performance optimization
   - DevOps and infrastructure patterns
   - Logging, monitoring, tracing
   - Error handling and resilience
   - Rate limiting and caching

6. **system-architecture-patterns-php-vs-go.md** (804 lines)
   - Hexagonal (ports and adapters) architecture
   - Clean Architecture
   - SOLID principles
   - Layered architecture
   - Event-driven architecture
   - Database integration patterns

7. **testing-patterns-php-vs-go.md** (1,550 lines)
   - Unit testing strategies
   - Integration testing
   - Test doubles (mocks, stubs, fakes)
   - Testing async/concurrent code
   - Property-based testing
   - Contract testing for microservices

8. **data-persistence-patterns-sql-vs-nosql.md** (317 lines)
   - SQL vs NoSQL tradeoffs
   - Relational database patterns
   - Document store patterns
   - Key-value store patterns
   - Data consistency models
   - Query optimization

9. **domain-driven-design-guide.md** (561 lines)
   - DDD philosophy and principles
   - Bounded contexts
   - Context mapping patterns
   - Ubiquitous language
   - Tactical DDD patterns (Entities, Value Objects, Aggregates)
   - Domain events and services
   - Repositories and factories
   - Layered architecture in DDD
   - Comparison with alternatives (MVC, CRUD, Active Record, etc.)
   - Decision framework for when to use DDD

### Test/Sample Files

10. **sample_text.txt** (1.1 KB)
    - Example text file for testing the TTS converter

### Asset Files

11. **An_Audio_Guide.txt** (35 KB) - Source text
12. **An_Audio_Guide.wav** (120 MB) - Generated audio output

---

## Special Patterns & Conventions Used

### Code Organization Patterns

1. **Single Class Pattern**
   - All functionality encapsulated in `TTSConverter` class
   - Clean separation of interactive UI from core logic
   - Easy to test and extend

2. **Configuration Persistence**
   - JSON-based user preferences
   - Stored in home directory (`~/.kokoro_tts_config.json`)
   - Improves UX through defaults memory

3. **Lazy Initialization**
   - TTS pipeline loaded only when needed
   - Reduces startup time if only file selection/validation is needed

4. **Interactive Workflow Pattern**
   - Step-by-step guided process
   - Confirmation before irreversible actions
   - Loop-back option to convert another file

### UI/UX Patterns

1. **Rich Library Usage**
   - Colored panels for headers
   - Tables for voice selection
   - Progress bars for long operations
   - Status spinners for indeterminate tasks
   - Styled error/success messages

2. **Inquirer Prompts**
   - List selections with arrow keys
   - Text input with defaults and validation
   - Confirmation dialogs
   - Custom value input support

3. **Progress Indication**
   - Spinner-based progress for streaming operations
   - Chunk-count updates during TTS conversion
   - File size reporting on completion

### Error Handling Patterns

1. **Dependency Validation**
   - Checks for missing Python packages at startup
   - Clear error messages with installation instructions
   - System dependency (espeak-ng) validation

2. **File Validation**
   - Input file existence and readability checks
   - Empty file detection
   - Output directory writable validation

3. **User Error Recovery**
   - Graceful cancellation (Ctrl+C) handling
   - Invalid input retry prompts
   - Informative error messages with context

### Platform Abstraction

1. **OS Detection**
   - Apple Silicon (ARM64) automatic detection
   - Platform-specific environment variable setup
   - Path expansion using `pathlib.Path`

2. **Audio Format Abstraction**
   - Temporary WAV file creation for conversion
   - Format-specific encoding (MP3 bitrate, OGG codec)
   - Automatic cleanup of temp files

### Configuration Patterns

1. **Config File Format**
   - Simple JSON structure
   - Three persisted preferences: voice, speed, format
   - Graceful fallback to defaults if file missing/corrupted

2. **Environment Variables**
   - `PYTORCH_ENABLE_MPS_FALLBACK` for Apple Silicon
   - Automatic detection and setup

---

## File Navigation & Import Structure

### Core Script Structure

```python
#!/usr/bin/env python3
# Imports (lines 6-31)
- Standard library: os, sys, platform, pathlib, json, typing
- Data processing: numpy, soundfile
- TTS engine: kokoro.KPipeline
- UI framework: rich (Console, Panel, Progress, Table)
- Interactive CLI: inquirer
- Audio conversion: pydub.AudioSegment

# Constants (lines 34-64)
- VOICES dict: 20 voices organized by gender
- CONFIG_FILE: ~/.kokoro_tts_config.json path

# Main Class (lines 67-431)
- TTSConverter implementation

# Entry Point (lines 433-440)
- main() function
- if __name__ == "__main__" guard
```

---

## Development Notes

### Key Design Decisions

1. **Single Script vs. Package Structure**
   - Chose single-file script for simplicity and easy distribution
   - All functionality self-contained for users to understand flow

2. **Rich over Plain Print**
   - Rich library investment for professional CLI appearance
   - Improves user confidence in the tool
   - Better progress communication for long operations

3. **Interactive over Argument-Based**
   - Inquirer prompts guide users through decisions
   - Reduces cognitive load
   - Config memory minimizes repetitive input

4. **Local Processing Only**
   - No cloud API dependencies
   - Privacy-focused (no data leaves user's machine)
   - Works offline after model download

### Potential Extensions

Based on the codebase patterns, these extensions would be natural:

1. Batch mode for multiple files
2. Command-line argument support for scripting
3. SSML support for advanced voice control
4. Pre-/post-processing pipeline (silence trimming, normalization)
5. Configuration file override via command-line args
6. Audio concatenation across files
7. Quality/bitrate settings for compressed formats

### Documentation as Learning Resource

The included documentation files represent a comprehensive exploration of:
- Backend design patterns applicable to both PHP and Go
- DDD principles and when to apply them
- Data persistence strategies
- System architecture approaches
- Testing methodologies
- Naming and convention standards
- Cross-cutting concerns (security, performance, DevOps)

This documentation is **separate from** the TTS application but coexists in the repository as a learning/reference resource.

---

## Environment & Tooling

### Version Control

- Repository type: Learning/Learning-project (not a git repo at creation)
- `.gitignore` configured for:
  - Audio files (WAV, MP3, OGG, FLAC)
  - Python artifacts (__pycache__, .pyc, .egg)
  - Virtual environment (.venv, venv, env)
  - IDE files (.vscode, .idea)
  - Model cache (.cache, .pt, .pth)
  - Configuration (.kokoro_tts_config.json)

### Python Tooling

- **Virtual Environment:** .venv directory present
- **Type Checking:** .mypy_cache present (mypy configured)
- **Package Management:** requirements.txt for pip

### Supported Platforms

- macOS (Intel and Apple Silicon)
- Linux (Ubuntu, Debian, and derivatives)
- Windows 10/11
- Minimum Python: 3.9

---

## Summary

This project combines:
- A **practical, well-structured CLI application** for text-to-speech conversion
- A **comprehensive learning resource** documenting backend design patterns, architecture, and conventions

The main application demonstrates good software engineering practices:
- Clear separation of concerns
- Robust error handling
- User-friendly interactive design
- Platform-aware implementation
- Configuration persistence

The learning documentation provides extensive reference material for backend developers working with PHP and Go, covering design patterns, architecture, testing, and operational concerns.

**CLAUDE.md generated:** November 8, 2025
- remember to always keep Claude.md up to date