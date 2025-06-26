import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinterdnd2 import DND_FILES, TkinterDnD
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet
import magic
import math
import os
import datetime
import numpy as np
from collections import Counter
import struct

class FileScope:
    def __init__(self, root):
        self.root = root
        self.root.title("📂 FileScope - See Beyond the Extension")
        self.root.geometry("850x650")
        self.root.configure(bg="#1e1e2f")  # Dark background

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", font=("Segoe UI", 11), padding=6, background="#4e4e9a", foreground="white")
        style.map("TButton", background=[("active", "#6c6cd1")])
        style.configure("TLabel", background="#1e1e2f", foreground="white", font=("Segoe UI", 13))

        # Title
        self.label = ttk.Label(root, text="🔍 Drag or Select a File to Analyze")
        self.label.pack(pady=(20, 10))

        # Drop Zone
        self.drop_zone = tk.Text(root, height=2, width=50, bg="#2a2a40", fg="#ffffff", font=("Consolas", 11))
        self.drop_zone.pack(pady=10)
        self.drop_zone.insert(tk.END, "📁 Drop file here or click to browse...")
        self.drop_zone.bind("<Button-1>", self.browse_file)
        self.drop_zone.drop_target_register(DND_FILES)
        self.drop_zone.dnd_bind("<<Drop>>", self.handle_drop)

        # Output Text Box
        self.output_text = tk.Text(root, height=15, width=90, bg="#121221", fg="#cfcfcf", font=("Consolas", 11), relief=tk.GROOVE, bd=1)
        self.output_text.pack(pady=15)

        # Entropy Canvas
        self.entropy_canvas = tk.Canvas(root, height=100, width=500, bg="#282c34", highlightthickness=1, highlightbackground="#555")
        self.entropy_canvas.pack(pady=10)

        # Export Button
        self.export_button = ttk.Button(root, text="📤 Export PDF Report", command=self.export_pdf)
        self.export_button.pack(pady=20)

        # Init file info
        self.file_path = None
        self.analysis_results = {}

    def handle_drop(self, event):
        dropped_file = event.data.strip("{}")  # Remove curly braces on Windows paths
        if os.path.isfile(dropped_file):
            self.file_path = dropped_file
            self.drop_zone.delete(1.0, tk.END)
            self.drop_zone.insert(tk.END, os.path.basename(self.file_path))
            self.analyze_file()

    def browse_file(self, event=None):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            self.drop_zone.delete(1.0, tk.END)
            self.drop_zone.insert(tk.END, os.path.basename(self.file_path))
            self.analyze_file()

    def analyze_file(self):
        if not self.file_path or not os.path.exists(self.file_path):
            messagebox.showerror("Error", "Invalid file path!")
            return

        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"Analyzing file: {self.file_path}\n...\n")
        self.entropy_canvas.delete("all")
        self.entropy_canvas.create_text(250, 50, text="(Entropy Graph Placeholder)", fill="white", font=("Segoe UI", 11, "italic"))

        # Run detection modules
        self.magic_number_check()
        self.entropy_analysis()
        self.header_spoof_check()
        self.byte_pattern_analysis()
        self.structure_validation()

        # Display results
        self.display_results()
        self.plot_entropy()

    def magic_number_check(self):
     import os
     import tkinter as tk
 
     # Initialize default results in case of failure
     self.analysis_results["magic"] = {
         "Detected Type": "Unknown",
         "Declared Type": "UNKNOWN",
         "Status": "Unknown",
         "Extension": "None",
         "Debug": "No analysis performed yet"
     }
 
     # Check if file exists and is readable
     if not os.path.isfile(self.file_path):
         debug_msg = f"Error: File {self.file_path} does not exist or is not a file"
         self.analysis_results["magic"]["Debug"] = debug_msg
         self.output_text.insert(tk.END, debug_msg + "\n")
         return
 
     # Attempt MIME type detection using python-magic
     file_type = "UNKNOWN"
     try:
         import magic
         mime = magic.Magic(mime=True)
         file_type = mime.from_file(self.file_path)
         self.file_type = file_type
         self.analysis_results["magic"]["Debug"] = f"MIME detection successful: {file_type}"
     except AttributeError as e:
         debug_msg = f"Error: python-magic not properly installed. Missing 'Magic' class. Install 'python-magic' or 'python-magic-bin'. Error: {str(e)}"
         self.analysis_results["magic"]["Debug"] = debug_msg
         self.output_text.insert(tk.END, debug_msg + "\n")
     except Exception as e:
         debug_msg = f"Error in MIME detection: {str(e)}"
         self.analysis_results["magic"]["Debug"] = debug_msg
         self.output_text.insert(tk.END, debug_msg + "\n")
 
     # Get file extension
     extension = os.path.splitext(self.file_path)[1].lower().lstrip('.')
    magic_db = [
            {
                "header": b"\xFF\xD8\xFF\xDB",
                "offset": 0,
                "extension": ["jpg", "jpeg"],
                "description": "JPEG raw or in the JFIF or Exif file format"
            },
            {
                "header": b"\x89PNG\r\n\x1A\n",
                "offset": 0,
                "extension": ["png"],
                "description": "Image encoded in the Portable Network Graphics format"
            },
            {
                "header": b"BM",
                "offset": 0,
                "extension": ["bmp", "dib"],
                "description": "BMP file, a bitmap format used mostly in Windows"
            },
            {
                "header": b"GIF87a",
                "offset": 0,
                "extension": ["gif"],
                "description": "GIF image file (GIF87a)"
            },
            {
                "header": b"GIF89a",
                "offset": 0,
                "extension": ["gif"],
                "description": "GIF image file (GIF89a)"
            },
            {
                "header": b"%PDF-",
                "offset": 0,
                "extension": ["pdf"],
                "description": "PDF document"
            },
            {
                "header": b"PK\x03\x04",
                "offset": 0,
                "extension": [
                    "zip", "aar", "apk", "docx", "epub", "ipa", "jar", "kmz", "maff",
                    "msix", "odp", "ods", "odt", "pk3", "pk4", "pptx", "usdz", "vsdx",
                    "xlsx", "xpi", "whl"
                ],
                "description": "ZIP file format and ZIP-based formats",
                "footer": b"PK\x05\x06",
                "footer_offset": -22
            },
            {
                "header": b"PK\x05\x06",
                "offset": 0,
                "extension": ["zip"],
                "description": "Empty ZIP archive"
            },
            {
                "header": b"PK\x07\x08",
                "offset": 0,
                "extension": ["zip"],
                "description": "Spanned ZIP archive (split file)"
            },
            {
                "header": b"\x7FELF",
                "offset": 0,
                "extension": ["elf", "bin", "o", "out", "prx", "so", "axf"],
                "description": "Executable and Linkable Format"
            },
            {
                "header": b"MZ",
                "offset": 0,
                "extension": [
                    "exe", "dll", "mui", "sys", "scr", "cpl", "ocx", "ax", "iec", "ime",
                    "rs", "tsp", "fon", "efi"
                ],
                "description": "DOS MZ executable"
            },
            {
                "header": b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
                "offset": 0,
                "extension": ["doc", "xls", "ppt", "msi", "msg"],
                "description": "Microsoft Compound File Binary Format (pre-2007 Office)"
            },
            {
                "header": b"RIFF",
                "offset": 0,
                "extension": ["wav"],
                "description": "Waveform Audio File Format (WAVE)",
                "footer": b"WAVE",
                "footer_offset": 8
            },
            {
                "header": b"\xFF\xFB",
                "offset": 0,
                "extension": ["mp3"],
                "description": "MP3 file without ID3 tag (type 1)"
            },
            {
                "header": b"\xFF\xF3",
                "offset": 0,
                "extension": ["mp3"],
                "description": "MP3 file without ID3 tag (type 2)"
            },
            {
                "header": b"\xFF\xF2",
                "offset": 0,
                "extension": ["mp3"],
                "description": "MP3 file without ID3 tag (type 3)"
            },
            {
                "header": b"ID3",
                "offset": 0,
                "extension": ["mp3"],
                "description": "MP3 file with ID3v2 metadata"
            },
            {
                "header": b"MThd",
                "offset": 0,
                "extension": ["mid", "midi"],
                "description": "MIDI sound file"
            },
            {
                "header": b"Rar!\x1A\x07\x00",
                "offset": 0,
                "extension": ["rar"],
                "description": "RAR archive v1.50+"
            },
            {
                "header": b"Rar!\x1A\x07\x01\x00",
                "offset": 0,
                "extension": ["rar"],
                "description": "RAR archive v5.00+"
            },
            {
                "header": b"\x1F\x8B",
                "offset": 0,
                "extension": ["gz", "tar.gz"],
                "description": "GZIP compressed file"
            },
            {
                "header": b"7z\xBC\xAF\x27\x1C",
                "offset": 0,
                "extension": ["7z"],
                "description": "7-Zip archive"
            },
            {
                "header": b"MSCF",
                "offset": 0,
                "extension": ["cab"],
                "description": "Microsoft Cabinet File"
            },
            {
                "header": b"\xEF\xBB\xBF",
                "offset": 0,
                "extension": ["txt"],
                "description": "UTF-8 Byte Order Mark"
            },
            {
                "header": b"\xFF\xFE",
                "offset": 0,
                "extension": ["txt"],
                "description": "UTF-16 Little Endian BOM"
            },
            {
                "header": b"\xFE\xFF",
                "offset": 0,
                "extension": ["txt"],
                "description": "UTF-16 Big Endian BOM"
            },
            {
                "header": b"<?xml ",
                "offset": 0,
                "extension": ["xml"],
                "description": "XML file"
            },
            {
                "header": b"{\\rtf1",
                "offset": 0,
                "extension": ["rtf"],
                "description": "Rich Text Format"
            },
            {
                "header": b"OggS",
                "offset": 0,
                "extension": ["ogg", "oga", "ogv"],
                "description": "Ogg media container"
            },
            {
                "header": b"RIFF",
                "offset": 0,
                "extension": ["avi"],
                "description": "AVI video file",
                "footer": b"AVI ",
                "footer_offset": 8
            },
            {
                "header": b"FLV",
                "offset": 0,
                "extension": ["flv"],
                "description": "Flash Video file"
            },
            {
                "header": b"CWS",
                "offset": 0,
                "extension": ["swf"],
                "description": "Compressed Adobe Flash file"
            },
            {
                "header": b"FWS",
                "offset": 0,
                "extension": ["swf"],
                "description": "Uncompressed Adobe Flash file"
            },
            {
                "header": b"OTTO",
                "offset": 0,
                "extension": ["otf"],
                "description": "OpenType font"
            },
            {
                "header": b"\x00\x01\x00\x00\x00",
                "offset": 0,
                "extension": ["ttf", "tte", "dfont"],
                "description": "TrueType font"
            },
            {
                "header": b"IsZ!",
                "offset": 0,
                "extension": ["isz"],
                "description": "Compressed ISO image"
            },
            {
                "header": b"DAA",
                "offset": 0,
                "extension": ["daa"],
                "description": "Direct Access Archive"
            },
            {
                "header": b"LfLe",
                "offset": 0,
                "extension": ["evt"],
                "description": "Windows Event Viewer (legacy)"
            },
            {
                "header": b"ElfFile",
                "offset": 0,
                "extension": ["evtx"],
                "description": "Windows Event Log (XML)"
            },
            {
                "header": b"regf",
                "offset": 0,
                "extension": ["dat", "hiv"],
                "description": "Windows Registry file"
            },
            {
                "header": b"!BDN",
                "offset": 0,
                "extension": ["pst"],
                "description": "Outlook Personal Storage Table"
            },
            {
                "header": b"LZIP",
                "offset": 0,
                "extension": ["lz", "lzip"],
                "description": "LZIP compressed file"
            },
            {
                "header": b"070707",
                "offset": 0,
                "extension": ["cpio"],
                "description": "CPIO archive file"
            },
            {
                "header": b"II*\x00",
                "offset": 0,
                "extension": ["tif", "tiff"],
                "description": "TIFF image (little-endian)"
            },
            {
                "header": b"MM\x00*",
                "offset": 0,
                "extension": ["tif", "tiff"],
                "description": "TIFF image (big-endian)"
            },
            {
                "header": b"DICM",
                "offset": 128,
                "extension": ["dcm"],
                "description": "DICOM medical file"
            },
            {
                "header": b"fLaC",
                "offset": 0,
                "extension": ["flac"],
                "description": "FLAC audio"
            },
            {
                "header": b".snd",
                "offset": 0,
                "extension": ["au", "snd"],
                "description": "Sun/Next .au audio file"
            },
            {
                "header": b"RIFF",
                "offset": 0,
                "extension": ["webp"],
                "description": "WebP image format",
                "footer": b"WEBP",
                "footer_offset": 8
            },
            {
                "header": b"\x00\x00\x00\x14ftypisom",
                "offset": 0,
                "extension": ["mp4", "m4a", "m4v"],
                "description": "MPEG-4 media file",
                "footer": b"isom",
                "footer_offset": 8
            },
            {
                "header": b"8BPS",
                "offset": 0,
                "extension": ["psd"],
                "description": "Adobe Photoshop file"
            },
            {
                "header": b"SQLite format 3",
                "offset": 0,
                "extension": ["sqlite", "db", "db3", "sqlite3"],
                "description": "SQLite database"
            },
            {
                "header": b"\xCA\xFE\xBA\xBE",
                "offset": 0,
                "extension": ["class"],
                "description": "Java class file"
            },
            {
                "header": b"\x1A\x45\xDF\xA3",
                "offset": 0,
                "extension": ["webm", "mkv", "mka", "mks"],
                "description": "Matroska media container"
            },
            {
                "header": b"\x00asm",
                "offset": 0,
                "extension": ["wasm"],
                "description": "WebAssembly binary"
            },
            {
                "header": b"\x00\x00\x01\x00",
                "offset": 0,
                "extension": ["ico"],
                "description": "Windows icon file"
            },
            {
                "header": b"\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C",
                "offset": 0,
                "extension": ["asf", "wma", "wmv"],
                "description": "Advanced Systems Format",
                "footer": b"\xA1\xDC\xAB\xA9",
                "footer_offset": 24
            },
            {
                "header": b"\x23\x21",
                "offset": 0,
                "extension": ["sh", "py", "pl", "rb", "script"],
                "description": "Shebang (#!) script"
            }
        ]

    def match_magic(file_bytes, magic_db):
        if not file_bytes:
            return None, "Empty file or no data read"
        
        for entry in magic_db:
            offset = entry.get("offset", 0)
            header = entry["header"]

            # Check header match
            if len(file_bytes) >= offset + len(header) and file_bytes[offset:offset + len(header)] == header:
                # Optional footer check
                footer = entry.get("footer")
                footer_offset = entry.get("footer_offset", None)

                if footer and footer_offset is not None:
                    if footer_offset < 0:
                        if len(file_bytes) < abs(footer_offset):
                            continue
                        if not file_bytes[footer_offset:].endswith(footer):
                            continue
                    else:
                        if len(file_bytes) < footer_offset + len(footer):
                            continue
                        if file_bytes[footer_offset:footer_offset + len(footer)] != footer:
                            continue

                return entry, None  # Match found
        return None, "No matching magic number found"

        try:
            # Read file content
            with open(self.file_path, "rb") as f:
                file_data = f.read()
                hex_data = file_data[:16].hex()
                self.output_text.insert(tk.END, f"File Header (hex): {hex_data}\n")
    
            # Match against magic_db
            match, debug_info = match_magic(file_data, magic_db)
    
            if match:
                detected_type = match["description"]
                extensions = ", ".join(match["extension"])
                debug_info = f"Matched magic number for {detected_type} at offset {match.get('offset', 0)}"
            else:
                detected_type = "Unknown"
                extensions = "None"
                debug_info = debug_info or "No matching magic number found"
    
            declared_type = file_type.split("/")[-1].upper() if file_type != "UNKNOWN" else "UNKNOWN"
            status = "SPOOFED" if detected_type.upper() != declared_type and detected_type != "Unknown" else "Valid"
    
            # Update results
            self.analysis_results["magic"] = {
                "Detected Type": detected_type,
                "Declared Type": declared_type,
                "Status": status,
                "Extension": extensions,
                "Debug": debug_info
            }
            self.output_text.insert(tk.END, f"Debug: {debug_info}\n")
    
        except Exception as e:
            error_msg = f"Failed to analyze magic number: {str(e)}"
            self.analysis_results["magic"] = {
                "Detected Type": "Error",
                "Declared Type": "UNKNOWN",
                "Status": "Error",
                "Extension": "None",
                "Debug": error_msg
            }
            self.output_text.insert(tk.END, f"Error in magic number check: {error_msg}\n")

    def entropy_analysis(self):
        try:
            with open(self.file_path, "rb") as f:
                data = f.read()

            if not data:
                self.analysis_results["entropy"] = {
                    "Entropy": 0.0,
                    "LSB Check": "No data to analyze"
                }
                return

            byte_counts = Counter(data)
            length = len(data)
            entropy = -sum((count / length) * math.log2(count / length) for count in byte_counts.values() if count > 0)

            lsb_suspicious = False
            detected_type = self.analysis_results.get("magic", {}).get("Detected Type", "").upper()
            if entropy > 7.8 and detected_type in ["PNG", "JPEG"]:
                lsb_suspicious = True

            self.analysis_results["entropy"] = {
                "Entropy": round(entropy, 2),
                "LSB Check": "Hidden bits suspected" if lsb_suspicious else "No hidden bits detected"
            }
        except Exception as e:
            self.analysis_results["entropy"] = {
                "Entropy": 0.0,
                "LSB Check": f"Error: {str(e)}"
            }
            self.output_text.insert(tk.END, f"Error in entropy analysis: {str(e)}\n")

    def header_spoof_check(self):
        try:
            with open(self.file_path, "rb") as f:
                header = f.read(512)

            is_pe = False
            if header[:2] == b"MZ":
                try:
                    e_lfanew = struct.unpack("<L", header[60:64])[0]
                    if e_lfanew < len(header) and header[e_lfanew:e_lfanew+4] == b"PE\0\0":
                        is_pe = True
                except:
                    pass

            declared_type = self.analysis_results.get("magic", {}).get("Declared Type", "").upper()
            spoof_detected = is_pe and declared_type not in ["EXE", "DLL"]

            self.analysis_results["spoof"] = {
                "Spoof Detected": "Yes" if spoof_detected else "No",
                "Details": "Mismatched PE header" if spoof_detected else "Header consistent"
            }
        except Exception as e:
            self.analysis_results["spoof"] = {
                "Spoof Detected": "Error",
                "Details": f"Error: {str(e)}"
            }
            self.output_text.insert(tk.END, f"Error in header spoof check: {str(e)}\n")

    def byte_pattern_analysis(self):
        try:
            with open(self.file_path, "rb") as f:
                data = f.read(1024)

            bigrams = Counter(zip(data, data[1:]))
            total = sum(bigrams.values())
            if total == 0:
                self.analysis_results["pattern"] = {
                    "Similarity to EXE": "0% match to known EXE"
                }
                return

            exe_bigrams = {(0x4D, 0x5A): 0.1, (0x50, 0x45): 0.05}
            similarity = sum(min(bigrams.get(k, 0) / total, v) for k, v in exe_bigrams.items()) / sum(exe_bigrams.values())

            self.analysis_results["pattern"] = {
                "Similarity to EXE": f"{int(similarity * 100)}% match to known EXE"
            }
        except Exception as e:
            self.analysis_results["pattern"] = {
                "Similarity to EXE": f"Error: {str(e)}"
            }
            self.output_text.insert(tk.END, f"Error in byte pattern analysis: {str(e)}\n")

    def structure_validation(self):
        try:
            valid = True
            details = "Structure valid"

            detected_type = self.analysis_results.get("magic", {}).get("Detected Type", "").upper()
            if detected_type == "ZIP":
                with open(self.file_path, "rb") as f:
                    data = f.read()
                    if not data.endswith(b"\x50\x4B\x05\x06"):
                        valid = False
                        details = "Invalid ZIP end of central directory"

            self.analysis_results["structure"] = {
                "Valid": "Yes" if valid else "No",
                "Details": details
            }
        except Exception as e:
            self.analysis_results["structure"] = {
                "Valid": "Error",
                "Details": f"Error: {str(e)}"
            }
            self.output_text.insert(tk.END, f"Error in structure validation: {str(e)}\n")

    def display_results(self):
        try:
            output = "FileScope Analysis Results\n" + "="*30 + "\n"
            output += f"File: {os.path.basename(self.file_path)}\n"
            output += f"Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M IST')}\n\n"
            output += "[SUMMARY]\n"
            output += f"Detected Type: {self.analysis_results['magic']['Detected Type']}\n"
            output += f"Declared Type: {self.analysis_results['magic']['Declared Type']}\n"
            output += f"Status: {self.analysis_results['magic']['Status']}\n"
            output += f"Risk Level: {'HIGH' if self.analysis_results['magic']['Status'] == 'SPOOFED' else 'LOW'}\n"
            output += f"Debug Info: {self.analysis_results['magic']['Debug']}\n\n"
    
            output += "[DETAILS]\n"
            output += f"- Magic Number: {self.analysis_results['magic']['Detected Type']}\n"
            output += f"- Extension: {self.analysis_results['magic']['Extension']}\n"
            output += f"- Structure Validity: {self.analysis_results['structure']['Valid']} ({self.analysis_results['structure']['Details']})\n"
            output += f"- Entropy Analysis: {self.analysis_results['entropy']['Entropy']} ({self.analysis_results['entropy']['LSB Check']})\n"
            output += f"- Spoof Check: {self.analysis_results['spoof']['Spoof Detected']} ({self.analysis_results['spoof']['Details']})\n"
            output += f"- Byte Pattern Similarity: {self.analysis_results['pattern']['Similarity to EXE']}\n"
    
            output += "\n[RECOMMENDATION]\n"
            output += "Quarantine the file immediately. DO NOT run on production systems." if self.analysis_results["magic"]["Status"] == "SPOOFED" else "File appears safe but verify before execution."
    
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, output)
        except Exception as e:
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, f"Error displaying results: {str(e)}\n")

    def plot_entropy(self):
        try:
            with open(self.file_path, "rb") as f:
                data = f.read(1024)

            if not data:
                self.entropy_canvas.delete("all")
                self.entropy_canvas.create_text(250, 50, text="No data to plot", fill="white", font=("Segoe UI", 11, "italic"))
                return

            chunk_size = 64
            entropies = []
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i+chunk_size]
                if chunk:
                    byte_counts = Counter(chunk)
                    length = len(chunk)
                    entropy = -sum((count / length) * math.log2(count / length) for count in byte_counts.values() if count > 0)
                    entropies.append(entropy)

            self.entropy_canvas.delete("all")
            max_width = 500
            bar_width = max_width // len(entropies) if entropies else 10
            for i, entropy in enumerate(entropies):
                height = (entropy / 8) * 80
                self.entropy_canvas.create_rectangle(i*bar_width, 100-height, (i+1)*bar_width, 100, fill="blue")
        except Exception as e:
            self.entropy_canvas.delete("all")
            self.entropy_canvas.create_text(250, 50, text=f"Error plotting entropy: {str(e)}", fill="white", font=("Segoe UI", 11, "italic"))

    def export_pdf(self):
        if not self.file_path or not self.analysis_results:
            messagebox.showwarning("Warning", "No analysis results to export!")
            return

        try:
            pdf_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
            if not pdf_path:
                return

            doc = SimpleDocTemplate(pdf_path, pagesize=letter)
            styles = getSampleStyleSheet()
            story = [
                Paragraph("FileScope Forensic Report", styles['Title']),
                Spacer(1, 12),
                Paragraph(f"File: {os.path.basename(self.file_path)}", styles['Normal']),
                Paragraph(f"Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M IST')}", styles['Normal']),
                Spacer(1, 12),
            ]

            data = [
                ["[SUMMARY]", ""],
                ["Detected Type", self.analysis_results['magic']['Detected Type']],
                ["Declared Type", self.analysis_results['magic']['Declared Type']],
                ["Status", self.analysis_results['magic']['Status']],
                ["Risk Level", "HIGH" if self.analysis_results['magic']['Status'] == "SPOOFED" else "LOW"],
                ["", ""],
                ["[DETAILS]", ""],
                ["Magic Number", self.analysis_results['magic']['Detected Type']],
                ["Extension", self.analysis_results['magic']['Extension']],
                ["Structure Validity", f"{self.analysis_results['structure']['Valid']} ({self.analysis_results['structure']['Details']})"],
                ["Entropy Analysis", f"{self.analysis_results['entropy']['Entropy']} ({self.analysis_results['entropy']['LSB Check']})"],
                ["Spoof Check", f"{self.analysis_results['spoof']['Spoof Detected']} ({self.analysis_results['spoof']['Details']})"],
                ["Byte Pattern Similarity", self.analysis_results['pattern']['Similarity to EXE']],
                ["", ""],
                ["[RECOMMENDATION]", ""],
                ["Recommendation", "Quarantine the file immediately. DO NOT run on production systems." if self.analysis_results["magic"]["Status"] == "SPOOFED" else "File appears safe but verify before execution."]
            ]

            table = Table(data)
            table.setStyle([('GRID', (0,0), (-1,-1), 1, (0,0,0))])
            story.append(table)
            story.append(Spacer(1, 12))
            story.append(Paragraph("Generated by FileScope v1.0", styles['Normal']))

            doc.build(story)
            messagebox.showinfo("Success", f"PDF report saved to {pdf_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export PDF: {str(e)}")

if __name__ == "__main__":
    root = TkinterDnD.Tk()  # Drag-and-drop enabled root
    app = FileScope(root)
    root.mainloop()