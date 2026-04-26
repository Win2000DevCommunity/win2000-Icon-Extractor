"""
win2000 Icon Strip Extractor — GUI
─────────────────────────────────
Open a Windows binary (.dll / .exe) or a raw .bmp file.
Extracts all BITMAP resources in-memory, shows every icon strip live,
lets you select / save individual icons or bulk-export as ZIP.

Usage:
    python icon_extractor_gui.py [binary_or_bmp ...]

Requirements:
    pip install PyQt6 pillow numpy pefile
"""

import sys, os, io, zipfile, tempfile, struct
from pathlib import Path
from statistics import median

import pefile
from PIL import Image
import numpy as np

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFileDialog, QScrollArea, QFrame,
    QProgressBar, QMessageBox, QGridLayout, QSizePolicy,
    QAbstractScrollArea, QTabWidget
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import (
    QPixmap, QImage, QFont, QColor, QPalette, QPainter,
    QDragEnterEvent, QDropEvent, QPen
)


# ══════════════════════════════════════════════════════════════════════════════
#  PE BITMAP EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════

RT_BITMAP = 2

def extract_bitmaps_from_binary(binary_path):
    """
    Parse a PE (.dll/.exe) and extract all RT_BITMAP resources in-memory.
    Returns sorted list of (resource_id, PIL_Image).

    BMP resources in PE files lack the 14-byte BITMAPFILEHEADER — we rebuild it:
      'BM' + file_size(4LE) + reserved(4) + pixel_data_offset=54(4LE)
    """
    pe = pefile.PE(binary_path, fast_load=False)
    pe.parse_data_directories()
    results = []

    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        pe.close()
        return results

    for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if getattr(res_type, 'id', None) != RT_BITMAP:
            continue
        for res_id_entry in res_type.directory.entries:
            rid = getattr(res_id_entry, 'id', None) or 0
            for lang in res_id_entry.directory.entries:
                rva  = lang.data.struct.OffsetToData
                size = lang.data.struct.Size
                raw  = pe.get_data(rva, size)
                header = (b'BM'
                          + (size + 14).to_bytes(4, 'little')
                          + b'\x00\x00\x00\x00'
                          + (54).to_bytes(4, 'little'))
                try:
                    img = Image.open(io.BytesIO(header + raw))
                    img.load()
                    results.append((rid, img))
                except Exception:
                    pass

    pe.close()
    results.sort(key=lambda x: x[0])
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  PE ICO EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════

RT_ICON       = 3
RT_GROUP_ICON = 14

def extract_ico_groups_from_binary(binary_path):
    """
    Extract RT_GROUP_ICON resources from a PE binary.
    For each group builds a single-image .ico per size variant from the
    matching RT_ICON raw data, then loads it as a PIL RGBA image.

    Returns sorted list of (group_id, [(size_label, PIL_RGBA_image), ...]).

    GRPICONDIRENTRY layout (14 bytes):
        BYTE  bWidth, bHeight, bColorCount, bReserved
        WORD  wPlanes, wBitCount
        DWORD dwBytesInRes
        WORD  nId   ← index into RT_ICON resources
    """
    pe = pefile.PE(binary_path, fast_load=False)
    pe.parse_data_directories()

    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        pe.close()
        return []

    # 1. Collect all RT_ICON raw blobs keyed by resource ID
    icon_raw = {}
    for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if getattr(res_type, 'id', None) != RT_ICON:
            continue
        for rid_entry in res_type.directory.entries:
            rid = getattr(rid_entry, 'id', None) or 0
            for lang in rid_entry.directory.entries:
                icon_raw[rid] = pe.get_data(
                    lang.data.struct.OffsetToData,
                    lang.data.struct.Size)

    # 2. Parse RT_GROUP_ICON directories
    results = []
    for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if getattr(res_type, 'id', None) != RT_GROUP_ICON:
            continue
        for rid_entry in res_type.directory.entries:
            gid = getattr(rid_entry, 'id', None) or 0
            for lang in rid_entry.directory.entries:
                grp = pe.get_data(lang.data.struct.OffsetToData,
                                  lang.data.struct.Size)
                if len(grp) < 6:
                    continue
                _res, _type, count = struct.unpack_from('<HHH', grp, 0)

                images = []
                for i in range(count):
                    base = 6 + i * 14
                    if base + 14 > len(grp):
                        break
                    bw, bh, bcc, _r, planes, bitcount, bytesinres = \
                        struct.unpack_from('<BBBBHHI', grp, base)
                    nId = struct.unpack_from('<H', grp, base + 12)[0]

                    if nId not in icon_raw:
                        continue
                    raw = icon_raw[nId]

                    # Build minimal single-image .ico:
                    # ICONDIR(6) + ICONDIRENTRY(16) + data
                    ico_bw = bw if bw < 256 else 0
                    ico_bh = bh if bh < 256 else 0
                    ico  = struct.pack('<HHH', 0, 1, 1)
                    ico += struct.pack('<BBBBHHII',
                                      ico_bw, ico_bh, bcc, 0,
                                      planes, bitcount, len(raw), 22)
                    ico += raw
                    try:
                        img   = Image.open(io.BytesIO(ico)).convert('RGBA')
                        label = f"{img.width}×{img.height}"
                        if bitcount:
                            label += f"  {bitcount}bpp"
                        images.append((label, img))
                    except Exception:
                        pass

                if images:
                    images.sort(key=lambda x: x[1].width, reverse=True)
                    results.append((gid, images))

    pe.close()
    results.sort(key=lambda x: x[0])
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  ICON STRIP EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════

def get_transparent_indices(img):
    if img.mode != 'P':
        return set()
    pal = img.getpalette()
    return {i for i in range(len(pal) // 3)
            if pal[i*3] > 200 and pal[i*3+1] < 50 and pal[i*3+2] > 200}


def make_transparent_mask(arr, t_indices):
    mask = np.zeros(arr.shape, dtype=bool)
    for idx in t_indices:
        mask |= (arr == idx)
    return mask


def despill(img, t_indices):
    if img.mode == 'P' and t_indices:
        arr    = np.array(img, dtype=int)
        rgba   = img.convert('RGBA')
        out    = np.array(rgba, dtype=int)
        t_mask = make_transparent_mask(arr, t_indices)
        out[t_mask, :] = 0
        r, g, b    = out[:,:,0], out[:,:,1], out[:,:,2]
        spill      = np.maximum(0, np.minimum(r, b) - g)
        out[:,:,0] = np.clip(r - spill, 0, 255)
        out[:,:,2] = np.clip(b - spill, 0, 255)
        out[:,:,3] = np.where(t_mask, 0, np.clip(255 - spill, 0, 255))
        return Image.fromarray(out.astype(np.uint8), 'RGBA')
    else:
        arr = np.array(img.convert('RGBA'), dtype=int)
        r, g, b    = arr[:,:,0], arr[:,:,1], arr[:,:,2]
        spill      = np.maximum(0, np.minimum(r, b) - g)
        arr[:,:,0] = np.clip(r - spill, 0, 255)
        arr[:,:,2] = np.clip(b - spill, 0, 255)
        arr[:,:,3] = np.clip(255 - spill, 0, 255)
        return Image.fromarray(arr.astype(np.uint8), 'RGBA')


def separator_runs(t_mask, axis):
    is_sep = np.all(t_mask, axis=axis)
    runs, start = [], None
    for i, v in enumerate(is_sep):
        if v and start is None:
            start = i
        elif not v and start is not None:
            runs.append((start, i - 1)); start = None
    if start is not None:
        runs.append((start, len(is_sep) - 1))
    return runs


def icon_width_from_separators(runs, total):
    if len(runs) < 2:
        return None
    mids  = [(s + e) / 2 for s, e in runs]
    gaps  = [mids[i+1] - mids[i] for i in range(len(mids) - 1)]
    if not gaps:
        return None
    rounded = round(median(gaps))
    if rounded < 2:
        return None
    n = round(total / rounded)
    return round(total / n) if n >= 1 else None


def best_divisor(width, height):
    if width <= height * 1.5:
        return width
    divs  = [d for d in range(1, width + 1) if width % d == 0]
    cands = [d for d in divs if 2 <= width // d <= 50 and d >= height // 2]
    if not cands:
        cands = [d for d in divs if d >= 4]
    return min(cands, key=lambda d: abs(d - height)) if cands else width


def find_icon_size(t_mask, w, h, has_t, is_vertical):
    primary, secondary = (w, h) if not is_vertical else (h, w)
    if primary % secondary == 0:
        return secondary
    if has_t:
        axis  = 0 if not is_vertical else 1
        inner = [(s, e) for s, e in separator_runs(t_mask, axis)
                 if s > 0 and e < primary - 1]
        if inner:
            w_sep = icon_width_from_separators(inner, primary)
            if w_sep and 1 <= primary // w_sep <= 50:
                return w_sep
    return best_divisor(primary, secondary)


def extract_icons_from_image(img):
    """Returns (icons_list, icon_size_px, is_vertical)."""
    w, h        = img.size
    t_indices   = get_transparent_indices(img)
    arr         = np.array(img)
    t_mask      = make_transparent_mask(arr, t_indices)
    is_vertical = h > w
    icon_sz     = find_icon_size(t_mask, w, h, bool(t_indices), is_vertical)
    primary     = h if is_vertical else w
    n           = (primary + icon_sz - 1) // icon_sz
    rgba        = despill(img, t_indices)
    icons = []
    for i in range(n):
        if is_vertical:
            y0 = i * icon_sz
            icon = rgba.crop((0, y0, w, min(y0 + icon_sz, h)))
        else:
            x0 = i * icon_sz
            icon = rgba.crop((x0, 0, min(x0 + icon_sz, w), h))
        icons.append(icon)
    return icons, icon_sz, is_vertical


# ══════════════════════════════════════════════════════════════════════════════
#  PIL → QPixmap
# ══════════════════════════════════════════════════════════════════════════════

def pil_to_qpixmap(pil_img):
    if pil_img.mode != 'RGBA':
        pil_img = pil_img.convert('RGBA')
    data = pil_img.tobytes('raw', 'RGBA')
    qi   = QImage(data, pil_img.width, pil_img.height,
                  QImage.Format.Format_RGBA8888)
    return QPixmap.fromImage(qi.copy())


# ══════════════════════════════════════════════════════════════════════════════
#  WORKER THREAD
# ══════════════════════════════════════════════════════════════════════════════

class LoadWorker(QThread):
    binary_found = pyqtSignal(str, int)            # path, bitmap_count
    strip_ready  = pyqtSignal(str, int, object, list, int)
    # (source_path, resource_id [-1 for raw bmp], strip_pil, icons, icon_sz)
    progress     = pyqtSignal(int, int)
    error        = pyqtSignal(str, str)
    all_done     = pyqtSignal()

    def __init__(self, paths):
        super().__init__()
        self.paths = paths

    def run(self):
        # Collect all work items first so we can report accurate progress
        work_items = []   # (source_path, resource_id_or_None, pil_image)
        for path in self.paths:
            ext = Path(path).suffix.lower()
            if ext == '.bmp':
                try:
                    img = Image.open(path); img.load()
                    work_items.append((path, None, img))
                except Exception as e:
                    self.error.emit(Path(path).name, str(e))
            else:
                try:
                    bitmaps = extract_bitmaps_from_binary(path)
                    self.binary_found.emit(path, len(bitmaps))
                    for rid, img in bitmaps:
                        work_items.append((path, rid, img))
                except Exception as e:
                    self.error.emit(Path(path).name, str(e))

        total = len(work_items)
        for i, (src, rid, img) in enumerate(work_items):
            self.progress.emit(i, total)
            try:
                icons, icon_sz, _ = extract_icons_from_image(img)
                self.strip_ready.emit(
                    src, rid if rid is not None else -1,
                    img, icons, icon_sz)
            except Exception as e:
                label = (f"ID {rid}" if rid is not None
                         else Path(src).name)
                self.error.emit(label, str(e))

        self.progress.emit(total, total)
        self.all_done.emit()


# ══════════════════════════════════════════════════════════════════════════════
#  ICO WORKER THREAD
# ══════════════════════════════════════════════════════════════════════════════

class IcoWorker(QThread):
    binary_found = pyqtSignal(str, int)          # path, group_count
    group_ready  = pyqtSignal(str, int, list)    # path, group_id, [(label, pil)]
    progress     = pyqtSignal(int, int)
    error        = pyqtSignal(str, str)
    all_done     = pyqtSignal()

    def __init__(self, paths):
        super().__init__()
        self.paths = paths

    def run(self):
        for path in self.paths:
            ext = Path(path).suffix.lower()
            if ext == '.bmp':
                continue   # BMPs have no ICO resources
            try:
                groups = extract_ico_groups_from_binary(path)
                self.binary_found.emit(path, len(groups))
                self.progress.emit(0, len(groups))
                for i, (gid, images) in enumerate(groups):
                    self.group_ready.emit(path, gid, images)
                    self.progress.emit(i + 1, len(groups))
            except Exception as e:
                self.error.emit(Path(path).name, str(e))
        self.all_done.emit()


# ══════════════════════════════════════════════════════════════════════════════
#  ICON TILE
# ══════════════════════════════════════════════════════════════════════════════

TILE  = 64
LABEL = 15

class IconTile(QWidget):
    def __init__(self, pil_icon, index, parent=None):
        super().__init__(parent)
        self.pil_icon  = pil_icon
        self.index     = index
        self._selected = False
        self.setFixedSize(TILE + 6, TILE + LABEL + 6)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(
            f"Icon #{index+1}  ·  {pil_icon.width}×{pil_icon.height} px\n"
            "Click to select  ·  Double-click to save")
        scaled = pil_icon.resize((TILE, TILE), Image.NEAREST)
        self._pixmap = pil_to_qpixmap(scaled)

    def paintEvent(self, _):
        p = QPainter(self)
        cell = 6
        c1, c2 = QColor('#262636'), QColor('#1e1e2e')
        for row in range(0, TILE, cell):
            for col in range(0, TILE, cell):
                clr = c1 if (row//cell + col//cell) % 2 == 0 else c2
                p.fillRect(3+col, 3+row,
                           min(cell, TILE-col), min(cell, TILE-row), clr)
        if self._selected:
            p.fillRect(2, 2, TILE+2, TILE+2, QColor(50, 130, 220, 60))
            p.setPen(QPen(QColor('#3c8ce6'), 2))
            p.drawRect(2, 2, TILE+1, TILE+1)
        else:
            p.setPen(QPen(QColor('#2a2a4a'), 1))
            p.drawRect(2, 2, TILE+1, TILE+1)
        if self._pixmap and not self._pixmap.isNull():
            x = 3 + (TILE - self._pixmap.width())  // 2
            y = 3 + (TILE - self._pixmap.height()) // 2
            p.drawPixmap(x, y, self._pixmap)
        p.setPen(QColor('#4a8ed6') if self._selected else QColor('#404060'))
        p.setFont(QFont('Consolas', 7))
        p.drawText(0, TILE+4, TILE+6, LABEL,
                   Qt.AlignmentFlag.AlignCenter, f"#{self.index+1}")
        p.end()

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._selected = not self._selected
            self.update()
        super().mousePressEvent(e)

    def mouseDoubleClickEvent(self, _):
        path, _ = QFileDialog.getSaveFileName(
            self, f"Save icon #{self.index+1}",
            f"icon_{self.index+1:04d}.png", "PNG (*.png)")
        if path:
            self.pil_icon.save(path)

    def set_selected(self, v):
        self._selected = v; self.update()

    def is_selected(self):
        return self._selected


# ══════════════════════════════════════════════════════════════════════════════
#  STRIP PANEL  (one bitmap resource = one panel)
# ══════════════════════════════════════════════════════════════════════════════

class StripPanel(QFrame):
    def __init__(self, source_path, resource_id,
                 strip_img, icons, icon_sz, parent=None):
        super().__init__(parent)
        self.source_path = source_path
        self.resource_id = resource_id   # -1 for raw .bmp files
        self.strip_img   = strip_img
        self.icons       = icons
        self.tiles       = []

        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setStyleSheet("""
            StripPanel {
                background:#111128;
                border:1px solid #22224a;
                border-radius:10px;
            }
        """)
        self.setSizePolicy(QSizePolicy.Policy.Expanding,
                           QSizePolicy.Policy.Minimum)

        root = QVBoxLayout(self)
        root.setSpacing(8)
        root.setContentsMargins(14, 10, 14, 12)

        # ── Header ───────────────────────────────────────────────
        hdr = QHBoxLayout()
        hdr.setSpacing(10)

        title_text = (f"Bitmap  ID {resource_id}" if resource_id >= 0
                      else Path(source_path).name)
        title_lbl = QLabel(title_text)
        title_lbl.setFont(QFont('Consolas', 10, QFont.Weight.Bold))
        title_lbl.setStyleSheet("color:#7ec8e3; background:transparent;")

        w, h = strip_img.size
        info_lbl = QLabel(
            f"{len(icons)} icon{'s' if len(icons)!=1 else ''}  ·  "
            f"{icon_sz} px  ·  src {w}×{h}")
        info_lbl.setFont(QFont('Consolas', 9))
        info_lbl.setStyleSheet("color:#555577; background:transparent;")

        # Raw strip preview
        preview_px = pil_to_qpixmap(strip_img.convert('RGB'))
        preview = QLabel()
        preview.setPixmap(preview_px.scaledToHeight(
            20, Qt.TransformationMode.FastTransformation))
        preview.setStyleSheet("border:1px solid #2a2a4a; background:#ff00ff;")
        preview.setToolTip("Original bitmap strip (raw, before despill)")

        btn_all  = self._btn("Select all",       self._select_all)
        btn_none = self._btn("None",              self._select_none)
        btn_sel  = self._btn("💾 Save selected",  self._save_selected, True)
        btn_all2 = self._btn("💾 Save all",       self._save_all,      True)

        hdr.addWidget(title_lbl)
        hdr.addWidget(info_lbl)
        hdr.addSpacing(6)
        hdr.addWidget(preview)
        hdr.addStretch()
        for b in (btn_all, btn_none, btn_sel, btn_all2):
            hdr.addWidget(b)
        root.addLayout(hdr)

        # Divider
        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet("background:#1e1e40; max-height:1px; border:none;")
        root.addWidget(div)

        # ── Icon grid ─────────────────────────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea { border:none; background:transparent; }
            QScrollBar:horizontal {
                background:#0d0d1a; height:5px; border-radius:3px; }
            QScrollBar::handle:horizontal {
                background:#3d3d6e; border-radius:3px; min-width:20px; }
            QScrollBar::add-line:horizontal,
            QScrollBar::sub-line:horizontal { width:0; }
        """)
        scroll.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setSizeAdjustPolicy(
            QAbstractScrollArea.SizeAdjustPolicy.AdjustToContents)

        grid_w = QWidget()
        grid_w.setStyleSheet("background:transparent;")
        grid = QGridLayout(grid_w)
        grid.setSpacing(3)
        grid.setContentsMargins(0, 0, 0, 0)

        n    = len(icons)
        cols = max(1, min(24, n))
        rows = (n + cols - 1) // cols

        for idx, icon in enumerate(icons):
            tile = IconTile(icon, idx)
            self.tiles.append(tile)
            grid.addWidget(tile, idx//cols, idx%cols)

        grid_w.setMinimumWidth(cols * (TILE + 7) + 4)
        scroll.setFixedHeight(min(rows, 2) * (TILE + LABEL + 7) + 10)
        scroll.setWidget(grid_w)
        root.addWidget(scroll)

    @staticmethod
    def _btn(text, slot, accent=False):
        btn = QPushButton(text)
        btn.setFixedHeight(25)
        if accent:
            btn.setStyleSheet("""
                QPushButton {
                    background:#0e2a4a; color:#7ec8e3;
                    border:1px solid #2d5a80; border-radius:4px;
                    padding:0 10px; font-size:10px; font-family:Consolas;
                }
                QPushButton:hover { background:#1a4070; }
            """)
        else:
            btn.setStyleSheet("""
                QPushButton {
                    background:#16162e; color:#7888aa;
                    border:1px solid #2a2a4e; border-radius:4px;
                    padding:0 10px; font-size:10px; font-family:Consolas;
                }
                QPushButton:hover { background:#222244; color:#aabbdd; }
            """)
        btn.clicked.connect(slot)
        return btn

    def _output_folder(self):
        out = QFileDialog.getExistingDirectory(self, "Choose output folder")
        if not out:
            return None
        stem = Path(self.source_path).stem
        if self.resource_id >= 0:
            folder = Path(out) / stem / f"bitmap_{self.resource_id}"
        else:
            folder = Path(out) / stem
        folder.mkdir(parents=True, exist_ok=True)
        return folder

    def _select_all(self):
        for t in self.tiles: t.set_selected(True)

    def _select_none(self):
        for t in self.tiles: t.set_selected(False)

    def _save_selected(self):
        sel = [t for t in self.tiles if t.is_selected()]
        if not sel:
            QMessageBox.information(self, "Nothing selected",
                "Click icon tiles to select them first.")
            return
        folder = self._output_folder()
        if not folder: return
        for t in sel:
            t.pil_icon.save(folder / f"{t.index+1:04d}.png")
        QMessageBox.information(self, "Saved",
            f"Saved {len(sel)} icon(s) to:\n{folder}")

    def _save_all(self):
        folder = self._output_folder()
        if not folder: return
        for i, icon in enumerate(self.icons):
            icon.save(folder / f"{i+1:04d}.png")
        QMessageBox.information(self, "Saved",
            f"Saved {len(self.icons)} icons to:\n{folder}")


# ══════════════════════════════════════════════════════════════════════════════
#  ICO GROUP PANEL  (one RT_GROUP_ICON entry = one panel)
# ══════════════════════════════════════════════════════════════════════════════

class IcoGroupPanel(QFrame):
    """
    Shows all size variants of a single icon group (.ico resource).
    Each variant is displayed as an IconTile; double-click saves that size.
    """
    def __init__(self, source_path, group_id, images, parent=None):
        """
        images: list of (size_label, PIL_RGBA_image) sorted largest first.
        """
        super().__init__(parent)
        self.source_path = source_path
        self.group_id    = group_id
        self.images      = images   # [(label, pil), ...]
        self.tiles       = []

        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setStyleSheet("""
            IcoGroupPanel {
                background:#0f1420;
                border:1px solid #1e2a4a;
                border-radius:10px;
            }
        """)
        self.setSizePolicy(QSizePolicy.Policy.Expanding,
                           QSizePolicy.Policy.Minimum)

        root = QVBoxLayout(self)
        root.setSpacing(8)
        root.setContentsMargins(14, 10, 14, 12)

        # ── Header ───────────────────────────────────────────────
        hdr = QHBoxLayout()
        hdr.setSpacing(10)

        title_lbl = QLabel(f"Icon  ID {group_id}")
        title_lbl.setFont(QFont('Consolas', 10, QFont.Weight.Bold))
        title_lbl.setStyleSheet("color:#a8d8a8; background:transparent;")

        sizes_txt = "  ·  ".join(lbl for lbl, _ in images)
        info_lbl  = QLabel(sizes_txt)
        info_lbl.setFont(QFont('Consolas', 9))
        info_lbl.setStyleSheet("color:#446644; background:transparent;")

        btn_save_ico = self._btn("💾 Save as .ico", self._save_ico, accent=True)
        btn_save_png = self._btn("💾 Save PNGs",    self._save_pngs, accent=True)

        hdr.addWidget(title_lbl)
        hdr.addWidget(info_lbl)
        hdr.addStretch()
        hdr.addWidget(btn_save_ico)
        hdr.addWidget(btn_save_png)
        root.addLayout(hdr)

        # Divider
        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet("background:#1e2a4a; max-height:1px; border:none;")
        root.addWidget(div)

        # ── Icon tiles (one per size variant) ─────────────────────
        tiles_row = QHBoxLayout()
        tiles_row.setSpacing(10)
        tiles_row.setContentsMargins(0, 0, 0, 0)

        for idx, (label, pil_img) in enumerate(images):
            col = QVBoxLayout()
            col.setSpacing(4)
            col.setAlignment(Qt.AlignmentFlag.AlignTop)

            tile = IconTile(pil_img, idx)
            self.tiles.append(tile)
            col.addWidget(tile)

            size_lbl = QLabel(label)
            size_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            size_lbl.setFont(QFont('Consolas', 8))
            size_lbl.setStyleSheet("color:#446644; background:transparent;")
            col.addWidget(size_lbl)

            tiles_row.addLayout(col)

        tiles_row.addStretch()
        root.addLayout(tiles_row)

    @staticmethod
    def _btn(text, slot, accent=False):
        btn = QPushButton(text)
        btn.setFixedHeight(25)
        if accent:
            btn.setStyleSheet("""
                QPushButton {
                    background:#0e2a1a; color:#a8d8a8;
                    border:1px solid #2d6a3d; border-radius:4px;
                    padding:0 10px; font-size:10px; font-family:Consolas;
                }
                QPushButton:hover { background:#1a4828; }
            """)
        else:
            btn.setStyleSheet("""
                QPushButton {
                    background:#16162e; color:#7888aa;
                    border:1px solid #2a2a4e; border-radius:4px;
                    padding:0 10px; font-size:10px; font-family:Consolas;
                }
                QPushButton:hover { background:#222244; color:#aabbdd; }
            """)
        btn.clicked.connect(slot)
        return btn

    def _save_ico(self):
        """Reconstruct a proper multi-size .ico file and save it."""
        path, _ = QFileDialog.getSaveFileName(
            self, f"Save icon group {self.group_id}",
            f"icon_{self.group_id}.ico",
            "ICO file (*.ico)")
        if not path:
            return
        # Build multi-image .ico
        n      = len(self.images)
        offset = 6 + n * 16   # ICONDIR + n * ICONDIRENTRY
        header = struct.pack('<HHH', 0, 1, n)
        entries, blobs = b'', b''
        for label, pil_img in self.images:
            buf = io.BytesIO()
            pil_img.save(buf, format='PNG')
            png = buf.getvalue()
            w   = pil_img.width  if pil_img.width  < 256 else 0
            h   = pil_img.height if pil_img.height < 256 else 0
            entries += struct.pack('<BBBBHHII',
                                   w, h, 0, 0, 1, 32, len(png),
                                   offset + len(blobs))
            blobs += png
        with open(path, 'wb') as f:
            f.write(header + entries + blobs)
        QMessageBox.information(self, "Saved",
            f"Saved {n}-size icon to:\n{path}")

    def _save_pngs(self):
        """Save each size variant as an individual PNG."""
        out = QFileDialog.getExistingDirectory(self, "Choose output folder")
        if not out:
            return
        stem   = Path(self.source_path).stem
        folder = Path(out) / stem / f"icon_{self.group_id}"
        folder.mkdir(parents=True, exist_ok=True)
        for label, pil_img in self.images:
            safe = label.replace('×','x').replace(' ','_').replace('/','_')
            pil_img.save(folder / f"{safe}.png")
        QMessageBox.information(self, "Saved",
            f"Saved {len(self.images)} PNG(s) to:\n{folder}")


# ══════════════════════════════════════════════════════════════════════════════
#  DROP ZONE
# ══════════════════════════════════════════════════════════════════════════════

class DropZone(QLabel):
    files_dropped  = pyqtSignal(list)
    folder_dropped = pyqtSignal(str)   # NEW: emits folder path

    _NORMAL = """QLabel {
        color:#404060; background:#0a0a18;
        border:2px dashed #222244; border-radius:10px; padding:18px;
    }"""
    _HOVER = """QLabel {
        color:#7ec8e3; background:#0c0c1e;
        border:2px dashed #5599cc; border-radius:10px; padding:18px;
    }"""
    _EXTS = {'.bmp', '.dll', '.exe', '.ocx', '.cpl', '.scr'}

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setMinimumHeight(90)
        self.setMaximumHeight(90)
        self.setFont(QFont('Consolas', 11))
        self.setText(
            "⬇   Drop  .dll / .exe / .ocx / .bmp  or a BMP folder  here"
            "   ·   click to browse")
        self.setStyleSheet(self._NORMAL)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
            self.setStyleSheet(self._HOVER)

    def dragLeaveEvent(self, _):
        self.setStyleSheet(self._NORMAL)

    def dropEvent(self, e):
        self.setStyleSheet(self._NORMAL)
        urls = e.mimeData().urls()
        files   = []
        folders = []
        for u in urls:
            p = u.toLocalFile()
            if Path(p).is_dir():
                folders.append(p)
            elif Path(p).suffix.lower() in self._EXTS:
                files.append(p)
        if files:
            self.files_dropped.emit(files)
        for folder in folders:
            self.folder_dropped.emit(folder)

    def mousePressEvent(self, _):
        from PyQt6.QtWidgets import QMenu
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background:#111128; color:#c8d0e8;
                border:1px solid #2a2a4e; border-radius:6px;
                padding:4px;
            }
            QMenu::item { padding:6px 20px; border-radius:4px; }
            QMenu::item:selected { background:#285580; }
        """)
        act_files  = menu.addAction("📄  Open files  (.dll / .exe / .bmp …)")
        act_folder = menu.addAction("📂  Open BMP folder")
        chosen = menu.exec(self.mapToGlobal(self.rect().center()))
        if chosen == act_files:
            paths, _ = QFileDialog.getOpenFileNames(
                self, "Open files", "",
                "Windows files (*.dll *.exe *.ocx *.cpl *.scr *.bmp);;"
                "All files (*.*)")
            if paths:
                self.files_dropped.emit(paths)
        elif chosen == act_folder:
            folder = QFileDialog.getExistingDirectory(
                self, "Select BMP folder")
            if folder:
                self.folder_dropped.emit(folder)


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN WINDOW
# ══════════════════════════════════════════════════════════════════════════════

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("win2000 Icon Extractor")
        self.resize(1150, 720)
        self.setMinimumSize(800, 500)
        self._panels: list[StripPanel] = []
        self._ico_panels: list[IcoGroupPanel] = []
        self._build_ui()

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        vl = QVBoxLayout(root)
        vl.setSpacing(0)
        vl.setContentsMargins(0, 0, 0, 0)

        # Title bar
        tbar = QWidget()
        tbar.setFixedHeight(52)
        tbar.setStyleSheet(
            "background:#07071a; border-bottom:1px solid #191936;")
        tbl = QHBoxLayout(tbar)
        tbl.setContentsMargins(20, 0, 20, 0)
        tbl.setSpacing(10)
        title = QLabel("⚙   win2000 Icon Extractor")
        title.setFont(QFont('Consolas', 13, QFont.Weight.Bold))
        title.setStyleSheet("color:#7ec8e3; background:transparent;")
        self.export_btn = self._tbtn("📦  Export all  →  ZIP", False)
        self.export_btn.clicked.connect(self._export_zip)
        self.clear_btn = self._tbtn("🗑  Clear", False, danger=True)
        self.clear_btn.clicked.connect(self._clear_all)
        tbl.addWidget(title); tbl.addStretch()
        tbl.addWidget(self.export_btn); tbl.addWidget(self.clear_btn)
        vl.addWidget(tbar)

        # Drop zone
        dw = QWidget()
        dw.setStyleSheet("background:#0a0a1a;")
        dwl = QVBoxLayout(dw)
        dwl.setContentsMargins(14, 8, 14, 6)
        self.drop_zone = DropZone()
        self.drop_zone.files_dropped.connect(self._on_files_dropped)
        self.drop_zone.folder_dropped.connect(self._on_folder_dropped)  # NEW
        dwl.addWidget(self.drop_zone)
        vl.addWidget(dw)

        # Progress bar
        self.prog = QProgressBar()
        self.prog.setFixedHeight(3)
        self.prog.setTextVisible(False)
        self.prog.setStyleSheet("""
            QProgressBar { background:#0a0a1a; border:none; }
            QProgressBar::chunk {
                background:qlineargradient(x1:0 y1:0 x2:1 y2:0,
                    stop:0 #1a4488, stop:0.5 #7ec8e3, stop:1 #1a4488); }
        """)
        self.prog.hide()
        vl.addWidget(self.prog)

        # ── Tabs ─────────────────────────────────────────────────
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border:none; background:#0a0a1a; }
            QTabBar::tab {
                background:#0d0d20; color:#444466;
                border:1px solid #1a1a3a; border-bottom:none;
                padding:6px 18px; font-family:Consolas; font-size:10px;
                border-top-left-radius:6px; border-top-right-radius:6px;
                margin-right:2px;
            }
            QTabBar::tab:selected {
                background:#0a0a1a; color:#7ec8e3;
                border-color:#285580;
            }
            QTabBar::tab:hover:!selected { background:#111128; color:#7888aa; }
        """)

        # Tab 1 — Bitmap Strips
        bmp_tab = QWidget()
        bmp_tab.setStyleSheet("background:#0a0a1a;")
        bmp_vl  = QVBoxLayout(bmp_tab)
        bmp_vl.setContentsMargins(0, 0, 0, 0)

        bmp_scroll = QScrollArea()
        bmp_scroll.setWidgetResizable(True)
        bmp_scroll.setStyleSheet("""
            QScrollArea { background:#0a0a1a; border:none; }
            QScrollBar:vertical {
                background:#0a0a1a; width:7px; border-radius:4px; }
            QScrollBar::handle:vertical {
                background:#262650; border-radius:4px; min-height:28px; }
            QScrollBar::handle:vertical:hover { background:#404080; }
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical { height:0; }
        """)
        self._res_w = QWidget()
        self._res_w.setStyleSheet("background:#0a0a1a;")
        self._res_l = QVBoxLayout(self._res_w)
        self._res_l.setSpacing(10)
        self._res_l.setContentsMargins(14, 10, 14, 14)
        self._res_l.addStretch()
        bmp_scroll.setWidget(self._res_w)
        bmp_vl.addWidget(bmp_scroll)
        self.tabs.addTab(bmp_tab, "🖼  Bitmap Strips")

        # Tab 2 — Icons (.ico)
        ico_tab = QWidget()
        ico_tab.setStyleSheet("background:#0a0a1a;")
        ico_vl  = QVBoxLayout(ico_tab)
        ico_vl.setContentsMargins(0, 0, 0, 0)

        ico_scroll = QScrollArea()
        ico_scroll.setWidgetResizable(True)
        ico_scroll.setStyleSheet("""
            QScrollArea { background:#0a0a1a; border:none; }
            QScrollBar:vertical {
                background:#0a0a1a; width:7px; border-radius:4px; }
            QScrollBar::handle:vertical {
                background:#1e3a26; border-radius:4px; min-height:28px; }
            QScrollBar::handle:vertical:hover { background:#2e5a3e; }
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical { height:0; }
        """)
        self._ico_w = QWidget()
        self._ico_w.setStyleSheet("background:#0a0a1a;")
        self._ico_l = QVBoxLayout(self._ico_w)
        self._ico_l.setSpacing(10)
        self._ico_l.setContentsMargins(14, 10, 14, 14)
        self._ico_l.addStretch()
        ico_scroll.setWidget(self._ico_w)
        ico_vl.addWidget(ico_scroll)
        self.tabs.addTab(ico_tab, "🔷  Icons  (.ico)")

        vl.addWidget(self.tabs, 1)

        # Status bar
        self.status = QLabel(
            "Ready  —  drop a  .dll / .exe / .ocx / .bmp  to begin")
        self.status.setFixedHeight(24)
        self.status.setFont(QFont('Consolas', 8))
        self.status.setStyleSheet("""
            QLabel {
                background:#05050f; color:#333355;
                border-top:1px solid #141430; padding-left:14px;
            }
        """)
        vl.addWidget(self.status)

    @staticmethod
    def _tbtn(text, enabled, danger=False):
        btn = QPushButton(text)
        btn.setEnabled(enabled)
        btn.setFixedHeight(30)
        if danger:
            btn.setStyleSheet("""
                QPushButton {
                    background:#141428; color:#333355;
                    border:1px solid #1e1e3e; border-radius:5px;
                    padding:0 14px; font-size:10px; font-family:Consolas; }
                QPushButton:enabled { color:#7777aa; }
                QPushButton:enabled:hover {
                    background:#280e0e; color:#dd6666; border-color:#4a2222; }
            """)
        else:
            btn.setStyleSheet("""
                QPushButton {
                    background:#141428; color:#222244;
                    border:1px solid #1e1e3e; border-radius:5px;
                    padding:0 14px; font-size:10px; font-family:Consolas; }
                QPushButton:enabled { color:#7ec8e3; border-color:#285580; }
                QPushButton:enabled:hover { background:#182840; }
            """)
        return btn

    # ── Slots ─────────────────────────────────────────────────────────────────

    def _on_files_dropped(self, paths):
        if not paths:
            self._set_status("⚠  No supported files found", error=True)
            return
        names = ", ".join(Path(p).name for p in paths[:3])
        if len(paths) > 3: names += f" +{len(paths)-3} more"
        self.prog.setMaximum(0)
        self.prog.show()
        self._set_status(f"Loading  {names}…")

        # BMP strip worker
        self._worker = LoadWorker(paths)
        self._worker.binary_found.connect(
            lambda p, c: self._set_status(
                f"Found {c} bitmap(s) in  {Path(p).name}…"))
        self._worker.strip_ready.connect(self._on_strip_ready)
        self._worker.progress.connect(
            lambda c, t: (self.prog.setMaximum(max(t,1)),
                          self.prog.setValue(c)))
        self._worker.error.connect(self._on_error)
        self._worker.all_done.connect(self._on_all_done)
        self._worker.start()

        # ICO worker (only for PE binaries — skip .bmp files)
        pe_paths = [p for p in paths
                    if Path(p).suffix.lower() not in ('.bmp',)]
        if pe_paths:
            self._ico_worker = IcoWorker(pe_paths)
            self._ico_worker.binary_found.connect(
                lambda p, c: self._set_status(
                    f"Found {c} icon group(s) in  {Path(p).name}…"))
            self._ico_worker.group_ready.connect(self._on_ico_group_ready)
            self._ico_worker.error.connect(self._on_error)
            self._ico_worker.all_done.connect(self._on_ico_all_done)
            self._ico_worker.start()

    # NEW: load all BMPs from a folder
    def _on_folder_dropped(self, folder):
        bmps = sorted(Path(folder).glob("*.bmp"))
        if not bmps:
            self._set_status(f"⚠  No .bmp files found in  {Path(folder).name}",
                             error=True)
            return
        self._on_files_dropped([str(p) for p in bmps])

    def _on_strip_ready(self, src, rid, strip_img, icons, icon_sz):
        panel = StripPanel(src, rid, strip_img, icons, icon_sz)
        self._panels.append(panel)
        self._res_l.insertWidget(self._res_l.count() - 1, panel)
        self.export_btn.setEnabled(True)
        self.clear_btn.setEnabled(True)

    def _on_error(self, label, msg):
        lbl = QLabel(f"⚠  {label}: {msg}")
        lbl.setStyleSheet(
            "color:#bb4444; font-family:Consolas; font-size:9px; "
            "background:transparent; padding:2px 6px;")
        self._res_l.insertWidget(self._res_l.count() - 1, lbl)

    def _on_all_done(self):
        self.prog.hide()
        total  = sum(len(p.icons) for p in self._panels)
        strips = len(self._panels)
        self._set_status(
            f"✓  {total} icons across {strips} strip(s)  "
            f"—  drag more files or click  Export all")

    # ── ICO slots ─────────────────────────────────────────────────────────────

    def _on_ico_group_ready(self, src, gid, images):
        panel = IcoGroupPanel(src, gid, images)
        self._ico_panels.append(panel)
        self._ico_l.insertWidget(self._ico_l.count() - 1, panel)
        # Switch to ICO tab to show activity
        self.tabs.setTabText(1, f"🔷  Icons  (.ico)  [{len(self._ico_panels)}]")
        self.export_btn.setEnabled(True)
        self.clear_btn.setEnabled(True)

    def _on_ico_all_done(self):
        if not self._ico_panels:
            self.tabs.setTabText(1, "🔷  Icons  (.ico)  [none]")

    def _export_zip(self):
        if not self._panels and not self._ico_panels: return
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Save ZIP", "icons_extracted.zip", "ZIP archive (*.zip)")
        if not save_path: return
        total = 0
        with zipfile.ZipFile(save_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Bitmap strips
            for panel in self._panels:
                stem = Path(panel.source_path).stem
                folder = (f"{stem}/bitmap_{panel.resource_id}"
                          if panel.resource_id >= 0 else stem)
                for i, icon in enumerate(panel.icons):
                    with tempfile.NamedTemporaryFile(
                            suffix='.png', delete=False) as tf:
                        icon.save(tf.name)
                        zf.write(tf.name, f"bitmaps/{folder}/{i+1:04d}.png")
                        os.unlink(tf.name)
                    total += 1
            # ICO groups — save each size as PNG + one .ico per group
            for panel in self._ico_panels:
                stem = Path(panel.source_path).stem
                folder = f"icons/{stem}/icon_{panel.group_id}"
                for label, pil_img in panel.images:
                    safe = label.replace('×','x').replace(' ','_')
                    with tempfile.NamedTemporaryFile(
                            suffix='.png', delete=False) as tf:
                        pil_img.save(tf.name)
                        zf.write(tf.name, f"{folder}/{safe}.png")
                        os.unlink(tf.name)
                    total += 1
        QMessageBox.information(self, "Export complete",
            f"Saved {total} item(s) to:\n{save_path}")

    def _clear_all(self):
        self._panels.clear()
        while self._res_l.count() > 1:
            item = self._res_l.takeAt(0)
            if item and item.widget():
                item.widget().deleteLater()
        self._ico_panels.clear()
        while self._ico_l.count() > 1:
            item = self._ico_l.takeAt(0)
            if item and item.widget():
                item.widget().deleteLater()
        self.tabs.setTabText(1, "🔷  Icons  (.ico)")
        self.export_btn.setEnabled(False)
        self.clear_btn.setEnabled(False)
        self._set_status(
            "Ready  —  drop a  .dll / .exe / .ocx / .bmp  to begin")

    def _set_status(self, text, error=False):
        color = "#bb4444" if error else "#333355"
        self.status.setStyleSheet(f"""
            QLabel {{
                background:#05050f; color:{color};
                border-top:1px solid #141430;
                padding-left:14px; font-family:Consolas; font-size:8px;
            }}
        """)
        self.status.setText(text)


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("win2000 Icon Extractor")
    app.setStyle("Fusion")

    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Window,          QColor("#0a0a1a"))
    pal.setColor(QPalette.ColorRole.WindowText,      QColor("#c8d0e8"))
    pal.setColor(QPalette.ColorRole.Base,            QColor("#111128"))
    pal.setColor(QPalette.ColorRole.AlternateBase,   QColor("#0e0e20"))
    pal.setColor(QPalette.ColorRole.ToolTipBase,     QColor("#0a0a1a"))
    pal.setColor(QPalette.ColorRole.ToolTipText,     QColor("#c8d0e8"))
    pal.setColor(QPalette.ColorRole.Text,            QColor("#c8d0e8"))
    pal.setColor(QPalette.ColorRole.Button,          QColor("#141428"))
    pal.setColor(QPalette.ColorRole.ButtonText,      QColor("#c8d0e8"))
    pal.setColor(QPalette.ColorRole.Highlight,       QColor("#285580"))
    pal.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    pal.setColor(QPalette.ColorRole.Link,            QColor("#7ec8e3"))
    app.setPalette(pal)

    win = MainWindow()

    # Optional: load files from CLI
    EXTS = {'.dll','.exe','.ocx','.cpl','.scr','.bmp'}
    cli  = [p for p in sys.argv[1:]
            if Path(p).suffix.lower() in EXTS]
    if cli:
        win._on_files_dropped(cli)

    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()