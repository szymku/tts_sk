# Kokoro TTS Converter

An interactive command-line tool for converting text files to high-quality audio using the Kokoro-82M text-to-speech model.

## Features

- **20 American English Voices** - Choose from 11 female and 9 male voices with different characteristics
- **Speed Control** - Adjust playback speed from 0.5x to 2.0x
- **Multiple Output Formats** - Save as WAV, MP3, or OGG
- **Progress Indicators** - Real-time progress tracking for long documents
- **Interactive CLI** - User-friendly prompts guide you through the conversion process
- **Configuration Memory** - Remembers your last settings for faster workflow
- **Local Processing** - Runs entirely on your machine, no API keys or internet required

## Prerequisites

### System Dependencies

You need to install `espeak-ng` on your system:

**macOS:**
```bash
brew install espeak-ng
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install espeak-ng
```

**Windows:**
Download and install from: https://github.com/espeak-ng/espeak-ng/releases

### Python

Python 3.9 or higher is required.

## Installation

1. Clone or download this repository:
```bash
cd /path/to/tts_sk
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Make the script executable (optional, macOS/Linux):
```bash
chmod +x tts_converter.py
```

## Usage

### Basic Usage

Run the interactive converter:

```bash
python tts_converter.py
```

The tool will guide you through:
1. Selecting your input text file
2. Choosing a voice (from 20 American English voices)
3. Setting playback speed
4. Selecting output format (WAV, MP3, or OGG)
5. Choosing where to save the audio file

### Available Voices

#### Female Voices (11)
- `af_heart` - Warm and friendly
- `af_alloy` - Professional and clear
- `af_aoede` - Melodic and expressive
- `af_bella` - Elegant and smooth
- `af_jessica` - Natural and conversational
- `af_kore` - Energetic and bright
- `af_nicole` - Balanced and versatile
- `af_nova` - Modern and dynamic
- `af_river` - Calm and soothing
- `af_sarah` - Clear and articulate
- `af_sky` - Light and airy

#### Male Voices (9)
- `am_adam` - Deep and authoritative
- `am_echo` - Resonant and strong
- `am_eric` - Friendly and approachable
- `am_fenrir` - Bold and commanding
- `am_liam` - Smooth and professional
- `am_michael` - Versatile and clear
- `am_onyx` - Rich and warm
- `am_puck` - Playful and energetic
- `am_santa` - Jolly and warm

### Speed Options

- **0.5x** - Very slow (great for learning/dictation)
- **0.75x** - Slow (clear and deliberate)
- **1.0x** - Normal (recommended for most uses)
- **1.25x** - Slightly faster
- **1.5x** - Fast (efficient for familiar content)
- **2.0x** - Very fast
- **Custom** - Enter any value between 0.5 and 2.0

### Output Formats

- **WAV** - Uncompressed, best quality, larger file size
- **MP3** - Compressed, good quality, smaller size (192kbps)
- **OGG** - Compressed, good quality, open format

## Example Workflow

1. Start the tool:
```bash
python tts_converter.py
```

2. When prompted, enter your text file path:
```
Enter the path to your text file: my_document.txt
```

3. Select a voice from the table (use arrow keys):
```
af_sarah - Sarah - Clear and articulate
```

4. Choose playback speed:
```
1.0x - Normal (recommended)
```

5. Select output format:
```
MP3 - Compressed (good quality, smaller size)
```

6. Confirm or modify the output path:
```
Enter output file path: my_document.mp3
```

7. Review and confirm:
```
Summary:
  Input: my_document.txt
  Voice: af_sarah
  Speed: 1.0x
  Format: MP3
  Output: my_document.mp3

Proceed with conversion? Yes
```

The tool will process your text and save the audio file!

## Configuration

Your preferences are automatically saved to `~/.kokoro_tts_config.json` and will be used as defaults for future conversions.

## Platform-Specific Notes

### macOS Apple Silicon
The tool automatically detects Apple Silicon Macs and enables the necessary fallback mode. No additional configuration needed.

### Windows
Make sure you have installed espeak-ng from the releases page before running the tool.

### Linux
The tool should work out of the box after installing espeak-ng via your package manager.

## Troubleshooting

### "Missing dependency" error
Make sure you've installed all requirements:
```bash
pip install -r requirements.txt
```

### "espeak-ng not found" error
Install espeak-ng for your platform (see Prerequisites section above).

### "Model loading failed" error
This usually means espeak-ng is not installed or not in your PATH. Install it and try again.

### Long processing time
- For very large documents, processing may take a few minutes
- The progress indicator will show you the current status
- Consider splitting very large documents into smaller files

### Audio quality issues
- WAV format provides the best quality
- MP3 at 192kbps is a good balance of quality and file size
- Try different voices to find the one that sounds best for your content

## Technical Details

- **Model**: Kokoro-82M (82 million parameters)
- **Architecture**: StyleTTS 2 + ISTFTNet
- **License**: Apache-2.0 (free for commercial use)
- **Audio Output**: 24kHz sample rate, mono
- **Processing**: Runs locally on CPU/GPU
- **Memory**: Efficient streaming for long documents

## Learning Documentation

- Idiomatic Go: Patterns, Libraries, Context, and Configuration — see [idiomatic-go-guide.md](idiomatic-go-guide.md)
- Idiomatic PHP 8.3: Symfony 7 & Laravel Web Backends — see [idiomatic-php8-guide.md](idiomatic-php8-guide.md)

## Credits

- **Kokoro-82M Model**: https://huggingface.co/hexgrad/Kokoro-82M
- **Model Developers**: hexgrad team
- **License**: Apache-2.0

## Support

For issues with the Kokoro model itself, visit:
- Model page: https://huggingface.co/hexgrad/Kokoro-82M
- GitHub: https://github.com/hexgrad/kokoro
- Discord: https://discord.gg/QuGxSWBfQy

For issues with this converter tool, check your installation and ensure all dependencies are properly installed.

## License

This tool is provided as-is. The Kokoro-82M model is licensed under Apache-2.0.
