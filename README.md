# win2000 Icon Extractor

<img width="1440" height="939" alt="image" src="https://github.com/user-attachments/assets/b31bd96e-7527-4727-ad99-b6b4bc22f98d" />

A small Python GUI tool for extracting Win98-style icon strips from BMP resources and icon groups from Windows PE files.

## Features

- Handles raw BMP toolbar/icon strips and extracts individual icons
- Scans `.dll`, `.exe`, `.ocx`, `.cpl`, `.scr` files for embedded icons
- Displays extracted bitmaps and icon groups in a modern retro-style UI
- Save individual icons as PNG or export all extracted assets to a ZIP archive
- Supports drag-and-drop and folder loading for BMP collections

## Requirements

- Python 3.14
- PyQt6
- Pillow
- NumPy

## Installation

```bash
python -m pip install PyQt6 pillow numpy
```

## Usage

```bash
python icon_extractor_gui.py
```

Then drag and drop supported files or open them via the drop zone.



Expected remote URL:

```bash
git@github.com:Win2000DevCommunity/win2000-Icon-Extractor.git
```

## License

MIT License
