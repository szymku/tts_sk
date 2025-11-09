#!/usr/bin/env python3
"""
Kokoro TTS Converter - Interactive CLI Tool
Converts text files to audio using the Kokoro-82M text-to-speech model
"""

import os
import sys
import platform
from pathlib import Path
import numpy as np
import soundfile as sf
from typing import Optional, List
import json

try:
    from kokoro import KPipeline
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.table import Table
    import inquirer
    from pydub import AudioSegment
except ImportError as e:
    print(f"Error: Missing dependency - {e}")
    print("\nPlease install required packages:")
    print("  pip install -r requirements.txt")
    print("\nAlso ensure espeak-ng is installed on your system:")
    print("  macOS: brew install espeak-ng")
    print("  Linux: sudo apt-get install espeak-ng")
    print("  Windows: Download from https://github.com/espeak-ng/espeak-ng/releases")
    sys.exit(1)

console = Console()

# American English voices (20 total)
VOICES = {
    "Female Voices": {
        "af_heart": "Heart - Warm and friendly",
        "af_alloy": "Alloy - Professional and clear",
        "af_aoede": "Aoede - Melodic and expressive",
        "af_bella": "Bella - Elegant and smooth",
        "af_jessica": "Jessica - Natural and conversational",
        "af_kore": "Kore - Energetic and bright",
        "af_nicole": "Nicole - Balanced and versatile",
        "af_nova": "Nova - Modern and dynamic",
        "af_river": "River - Calm and soothing",
        "af_sarah": "Sarah - Clear and articulate",
        "af_sky": "Sky - Light and airy"
    },
    "Male Voices": {
        "am_adam": "Adam - Deep and authoritative",
        "am_echo": "Echo - Resonant and strong",
        "am_eric": "Eric - Friendly and approachable",
        "am_fenrir": "Fenrir - Bold and commanding",
        "am_liam": "Liam - Smooth and professional",
        "am_michael": "Michael - Versatile and clear",
        "am_onyx": "Onyx - Rich and warm",
        "am_puck": "Puck - Playful and energetic",
        "am_santa": "Santa - Jolly and warm"
    }
}

CONFIG_FILE = Path.home() / ".kokoro_tts_config.json"


class TTSConverter:
    def __init__(self):
        self.pipeline = None
        self.config = self.load_config()
        self.check_platform()

    def check_platform(self):
        """Check platform and set environment variables if needed"""
        if platform.system() == "Darwin" and platform.machine() == "arm64":
            # macOS Apple Silicon - set MPS fallback
            os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "1"
            console.print("[yellow]Info: Detected macOS Apple Silicon - MPS fallback enabled[/yellow]")

    def load_config(self) -> dict:
        """Load saved configuration"""
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {
            "last_voice": "af_sarah",
            "last_speed": 1.0,
            "last_format": "wav"
        }

    def save_config(self):
        """Save configuration for next run"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            console.print(f"[yellow]Warning: Could not save config - {e}[/yellow]")

    def display_welcome(self):
        """Display welcome banner"""
        console.print(Panel.fit(
            "[bold cyan]Kokoro TTS Converter[/bold cyan]\n"
            "[dim]High-quality text-to-speech conversion using Kokoro-82M[/dim]\n"
            "[dim]American English - 20 voices available[/dim]",
            border_style="cyan"
        ))

    def select_input_file(self) -> Optional[Path]:
        """Interactive file selection"""
        questions = [
            inquirer.Text('file_path',
                         message="Enter the path to your text file",
                         default="")
        ]

        answers = inquirer.prompt(questions)
        if not answers:
            return None

        file_path = Path(answers['file_path']).expanduser()

        if not file_path.exists():
            console.print(f"[red]Error: File not found: {file_path}[/red]")
            return None

        if not file_path.is_file():
            console.print(f"[red]Error: Not a file: {file_path}[/red]")
            return None

        return file_path

    def select_voice(self) -> str:
        """Interactive voice selection"""
        console.print("\n[bold]Available Voices:[/bold]")

        # Create a table to display voices
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Voice ID", style="cyan")
        table.add_column("Description", style="white")

        voice_list = []
        for category, voices in VOICES.items():
            table.add_row(f"[bold]{category}[/bold]", "", style="yellow")
            for voice_id, description in voices.items():
                table.add_row(f"  {voice_id}", description)
                voice_list.append((voice_id, f"{voice_id} - {description}"))

        console.print(table)

        # Create selection choices
        choices = [desc for _, desc in voice_list]

        questions = [
            inquirer.List('voice',
                         message="Select a voice",
                         choices=choices,
                         default=next((desc for vid, desc in voice_list
                                     if vid == self.config["last_voice"]), choices[0]))
        ]

        answers = inquirer.prompt(questions)
        if not answers:
            return self.config["last_voice"]

        # Extract voice ID from selection
        selected = answers['voice']
        voice_id = selected.split(' - ')[0].strip()

        self.config["last_voice"] = voice_id
        return voice_id

    def select_speed(self) -> float:
        """Interactive speed selection"""
        questions = [
            inquirer.List('speed',
                         message="Select playback speed",
                         choices=[
                             ('0.5x - Very slow', 0.5),
                             ('0.75x - Slow', 0.75),
                             ('1.0x - Normal (recommended)', 1.0),
                             ('1.25x - Slightly faster', 1.25),
                             ('1.5x - Fast', 1.5),
                             ('2.0x - Very fast', 2.0),
                             ('Custom...', 'custom')
                         ],
                         default=1.0)
        ]

        answers = inquirer.prompt(questions)
        if not answers:
            return self.config["last_speed"]

        speed = answers['speed']

        if speed == 'custom':
            custom_q = [
                inquirer.Text('custom_speed',
                             message="Enter custom speed (0.5 - 2.0)",
                             default=str(self.config["last_speed"]),
                             validate=lambda _, x: 0.5 <= float(x) <= 2.0)
            ]
            custom_ans = inquirer.prompt(custom_q)
            if custom_ans:
                speed = float(custom_ans['custom_speed'])
            else:
                speed = self.config["last_speed"]

        self.config["last_speed"] = speed
        return speed

    def select_output_format(self) -> str:
        """Interactive output format selection"""
        questions = [
            inquirer.List('format',
                         message="Select output format",
                         choices=[
                             ('WAV - Uncompressed (best quality)', 'wav'),
                             ('MP3 - Compressed (good quality, smaller size)', 'mp3'),
                             ('OGG - Compressed (good quality, open format)', 'ogg')
                         ],
                         default=self.config["last_format"])
        ]

        answers = inquirer.prompt(questions)
        if not answers:
            return self.config["last_format"]

        fmt = answers['format']
        self.config["last_format"] = fmt
        return fmt

    def select_output_path(self, input_file: Path, output_format: str) -> Path:
        """Interactive output path selection"""
        default_output = input_file.with_suffix(f'.{output_format}')

        questions = [
            inquirer.Text('output_path',
                         message="Enter output file path",
                         default=str(default_output))
        ]

        answers = inquirer.prompt(questions)
        if not answers:
            return default_output

        return Path(answers['output_path']).expanduser()

    def read_text_file(self, file_path: Path) -> Optional[str]:
        """Read text from file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                text = f.read()

            if not text.strip():
                console.print("[red]Error: File is empty[/red]")
                return None

            # Show preview
            preview = text[:200] + "..." if len(text) > 200 else text
            console.print(f"\n[bold]Text preview:[/bold]\n{preview}\n")
            console.print(f"[dim]Total characters: {len(text)}[/dim]")

            return text
        except Exception as e:
            console.print(f"[red]Error reading file: {e}[/red]")
            return None

    def initialize_pipeline(self):
        """Initialize the TTS pipeline"""
        if self.pipeline is None:
            with console.status("[bold green]Loading Kokoro TTS model..."):
                try:
                    self.pipeline = KPipeline(lang_code='a')  # American English
                    console.print("[green]Model loaded successfully![/green]")
                except Exception as e:
                    console.print(f"[red]Error loading model: {e}[/red]")
                    console.print("\n[yellow]Please ensure espeak-ng is installed:[/yellow]")
                    console.print("  macOS: brew install espeak-ng")
                    console.print("  Linux: sudo apt-get install espeak-ng")
                    console.print("  Windows: https://github.com/espeak-ng/espeak-ng/releases")
                    raise

    def convert_text_to_speech(self, text: str, voice: str, speed: float) -> List[np.ndarray]:
        """Convert text to speech and return audio chunks"""
        self.initialize_pipeline()

        # Generate speech with progress indicator
        generator = self.pipeline(text, voice=voice, speed=speed, split_pattern=r'\n+')

        audio_chunks = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            # We don't know total in advance, so we'll just show a spinner
            task = progress.add_task("[cyan]Converting text to speech...", total=None)

            chunk_count = 0
            for i, (_graphemes, _phonemes, audio) in enumerate(generator):
                audio_chunks.append(audio)
                chunk_count = i + 1
                progress.update(task, description=f"[cyan]Processing chunk {chunk_count}...")

            progress.update(task, completed=True,
                          description=f"[green]Completed! Processed {chunk_count} chunk(s)")

        return audio_chunks

    def save_audio(self, audio_chunks: List[np.ndarray], output_path: Path, output_format: str):
        """Save audio chunks to file"""
        # Combine all chunks
        if len(audio_chunks) > 1:
            full_audio = np.concatenate(audio_chunks)
        else:
            full_audio = audio_chunks[0]

        # Save as WAV first
        temp_wav = output_path.with_suffix('.wav') if output_format != 'wav' else output_path

        with console.status(f"[bold green]Saving audio..."):
            sf.write(str(temp_wav), full_audio, 24000)

        # Convert to other formats if needed
        if output_format != 'wav':
            with console.status(f"[bold green]Converting to {output_format.upper()}..."):
                audio = AudioSegment.from_wav(str(temp_wav))

                if output_format == 'mp3':
                    audio.export(str(output_path), format='mp3', bitrate='192k')
                elif output_format == 'ogg':
                    audio.export(str(output_path), format='ogg', codec='libvorbis')

                # Remove temp WAV file
                temp_wav.unlink()

        # Calculate file size
        file_size = output_path.stat().st_size
        size_mb = file_size / (1024 * 1024)

        console.print(f"\n[bold green]Success![/bold green]")
        console.print(f"Audio saved to: [cyan]{output_path}[/cyan]")
        console.print(f"File size: [cyan]{size_mb:.2f} MB[/cyan]")
        console.print(f"Duration: [cyan]{len(full_audio) / 24000:.2f} seconds[/cyan]")

    def run(self):
        """Main interactive loop"""
        self.display_welcome()

        try:
            # Step 1: Select input file
            console.print("\n[bold]Step 1: Input File[/bold]")
            input_file = self.select_input_file()
            if not input_file:
                return

            # Step 2: Read text
            text = self.read_text_file(input_file)
            if not text:
                return

            # Step 3: Select voice
            console.print("\n[bold]Step 2: Voice Selection[/bold]")
            voice = self.select_voice()

            # Step 4: Select speed
            console.print("\n[bold]Step 3: Playback Speed[/bold]")
            speed = self.select_speed()

            # Step 5: Select output format
            console.print("\n[bold]Step 4: Output Format[/bold]")
            output_format = self.select_output_format()

            # Step 6: Select output path
            console.print("\n[bold]Step 5: Output Location[/bold]")
            output_path = self.select_output_path(input_file, output_format)

            # Confirmation
            console.print("\n[bold]Summary:[/bold]")
            console.print(f"  Input: [cyan]{input_file}[/cyan]")
            console.print(f"  Voice: [cyan]{voice}[/cyan]")
            console.print(f"  Speed: [cyan]{speed}x[/cyan]")
            console.print(f"  Format: [cyan]{output_format.upper()}[/cyan]")
            console.print(f"  Output: [cyan]{output_path}[/cyan]")

            questions = [
                inquirer.Confirm('proceed',
                               message="Proceed with conversion?",
                               default=True)
            ]

            answers = inquirer.prompt(questions)
            if not answers or not answers['proceed']:
                console.print("[yellow]Conversion cancelled.[/yellow]")
                return

            # Step 7: Convert
            console.print("\n[bold]Step 6: Converting...[/bold]")
            audio_chunks = self.convert_text_to_speech(text, voice, speed)

            # Step 8: Save
            self.save_audio(audio_chunks, output_path, output_format)

            # Save config for next time
            self.save_config()

            # Ask if user wants to convert another file
            questions = [
                inquirer.Confirm('another',
                               message="Convert another file?",
                               default=False)
            ]

            answers = inquirer.prompt(questions)
            if answers and answers['another']:
                console.print("\n" + "="*60 + "\n")
                self.run()

        except KeyboardInterrupt:
            console.print("\n\n[yellow]Conversion cancelled by user.[/yellow]")
        except Exception as e:
            console.print(f"\n[red]Error: {e}[/red]")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")


def main():
    """Entry point"""
    converter = TTSConverter()
    converter.run()


if __name__ == "__main__":
    main()
