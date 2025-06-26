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
        # Placeholder logic
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"Analyzing file: {self.file_path}\n...\n")
        # You can add actual analysis logic here
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

        def export_pdf(self):
         messagebox.showinfo("Export", "Report exported (placeholder).")

    def magic_number_check(self):
        try:
          mime = magic.Magic(mime=True)
          file_type = mime.from_file(self.file_path)
        except Exception:
         file_type = "UNKNOWN"

        extension = os.path.splitext(self.file_path)[1].lower()

        magic_db = {
            b"\x23\x21": "Shebang Script",
            b"\xFF\xD8\xFF\xDB": "JPEG (JFIF/Exif)",
            b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A": "PNG",
            b"\x42\x4D": "BMP",
            b"\x47\x49\x46\x38\x37\x61": "GIF87a",
            b"\x47\x49\x46\x38\x39\x61": "GIF89a",
            b"\x25\x50\x44\x46\x2D": "PDF",
            b"\x50\x4B\x03\x04": "ZIP/OOXML",
            b"\x50\x4B\x05\x06": "ZIP (empty)",
            b"\x50\x4B\x07\x08": "ZIP (spanned)",
            b"\x7F\x45\x4C\x46": "ELF",
            b"\x4D\x5A": "DOS MZ (EXE)",
            b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1": "MS Office (DOC/XLS/PPT old)",
            b"\x52\x49\x46\x46": "RIFF (WAV/AVI)",
            b"\xFF\xFB": "MP3 (No ID3)",
            b"\xFF\xF3": "MP3 (No ID3)",
            b"\xFF\xF2": "MP3 (No ID3)",
            b"\x49\x44\x33": "MP3 (ID3v2)",
            b"\x4D\x54\x68\x64": "MIDI",
            b"\x52\x61\x72\x21\x1A\x07\x00": "RAR v1.5",
            b"\x52\x61\x72\x21\x1A\x07\x01\x00": "RAR v5.0",
            b"\x1F\x8B": "GZIP",
            b"\x37\x7A\xBC\xAF\x27\x1C": "7-Zip",
            b"\x4D\x53\x43\x46": "CAB",
            b"\xEF\xBB\xBF": "UTF-8 BOM (Text)",
            b"\xFF\xFE": "UTF-16LE BOM (Text)",
            b"\xFE\xFF": "UTF-16BE BOM (Text)",
            b"\x3C\x3F\x78\x6D\x6C\x20": "XML",
            b"\x7B\x5C\x72\x74\x66\x31": "RTF",
            b"\x4F\x67\x67\x53": "Ogg",
            b"\x41\x56\x49\x20": "AVI",
            b"\x46\x4C\x56": "FLV",
            b"\x43\x57\x53": "SWF (Compressed)",
            b"\x46\x57\x53": "SWF (Uncompressed)",
            b"\x4F\x54\x54\x4F": "OTF Font",
            b"\x00\x01\x00\x00\x00": "TTF Font",
            b"\x49\x73\x5A\x21": "ISZ",
            b"\x44\x41\x41": "DAA",
            b"\x4C\x66\x4C\x65": "EVT",
            b"\x45\x6C\x66\x46\x69\x6C\x65": "EVTX",
            b"\x72\x65\x67\x66": "Windows Registry",
            b"\x21\x42\x44\x4E": "PST",
            b"\x4C\x5A\x49\x50": "LZIP",
            b"\x30\x37\x30\x37\x30\x37": "CPIO",
            b"\x49\x49\x2A\x00": "TIFF (LE)",
            b"\x4D\x4D\x00\x2A": "TIFF (BE)",
            b"\x49\x49\x2B\x00": "BigTIFF (LE)",
            b"\x4D\x4D\x00\x2B": "BigTIFF (BE)",
            b"\x44\x49\x43\x4D": "DICOM",
            b"\x66\x4C\x61\x43": "FLAC",
            b"\x2E\x73\x6E\x64": "AU/SND",
            b"\x25\x21\x50\x53": "PostScript",
            b"\x3C\x3C\x3C\x20": "VDI (Oracle)",
            b"\x63\x6F\x6E\x65\x63\x74\x69\x78": "VHD",
            b"\x76\x68\x64\x78\x66\x69\x6C\x65": "VHDX",
            b"\xAA\xAA\xAA\xAA": "Crowdstrike SYS",
            b"\x43\x44\x30\x30\x31": "ISO9660",
            b"\x4D\x53\x48\x7C": "HL7 (MSH)",
            b"\x42\x53\x48\x7C": "HL7 (BSH)",
            b"\x52\x49\x46\x46": "WebP (WEBP)",  # Special case: needs 8 bytes offset to confirm 'WEBP'
            b"\x00\x00\x00\x14\x66\x74\x79\x70\x69\x73\x6F\x6D": "MP4/M4A/M4V",
            b"\x46\x72\x6F\x6D\x48\x65\x61\x64": "PSD",
            b"\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33": "SQLite",
            b"\x28\x66\x61\x74\x20\x63\x6F\x64\x65\x29": "Java Class",
            b"\xCA\xFE\xBA\xBE": "Java Class",
            b"\x43\x61\x66\x66\x65\x69\x6E\x65": "Java Class (Variant)",
            b"\x6B\x64\x6D\x66": "KDM",
            b"\x44\x45\x41\x44\x42\x45\x45\x46": "DEB",
            b"\x2E\x72\x70\x6D": "RPM",
            b"\xF0\xED\xF0\xED": "IMG (Apple)",
            b"\x41\x52\x43\x01": "ARC (FreeArc)",
            b"\x41\x52\x43\x00": "ARC (FreeArc Alt)",
            b"\x1A\x45\xDF\xA3": "WEBM/MKV/MKA",
            b"\xF7\xFF\xFF\xFF\xC8\xFF\xFF\xFF\xF6\xFF\xFF\xFF": "DMG (Apple)",
            b"\x00\x61\x73\x6D": "WASM",
            b"\x45\x58\x54\x33": "EXT3/EXT4",
            b"\x00" * 16: "BIN/DAT (Zero Filled)",
            b"\x00\x00\x01\x00": "CUR/ICO",
            b"\x41\x43\x31\x30": "DWG/DXF",
            b"\x3B\x44\x57\x47\x44\x69\x73\x6B\x46\x69\x6C\x65": "DWG (Alt)",
            b"\x30\x30\x30\x30\x4C\x48\x53": "LZH/LHA",
            b"\x5A\x4F\x4F": "ZOO",
            b"\x41\x44\x49\x46": "ADF",
            b"\x4D\x53\x4A\x45\x54": "MDB",
            b"\x53\x71\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33": "SQLite (Alt)",
            b"\x00\x00\x00\x0C\x6A\x46\x54\x59\x50\x6D\x6A\x70\x32": "JPEG 2000 (JP2)",
            b"\x4C\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46": "LNK",
            b"\x00\x00\x01\xBA": "MPG/MPEG/DAT",
            b"\x00\x00\x01\xB3": "MPG/MPEG",
            b"\x00\x00\x01\xB6": "MPG/MPEG",
            b"\x00\x00\x01\xB7": "MPG/MPEG",
            b"\x00\x00\x01\xB8": "MPG/MPEG",
            b"\x00\x00\x01\xB9": "MPG/MPEG",
            b"\x00\x00\x01\xBC": "MPG/MPEG",
            b"\x00\x00\x01\xBE": "MPG/MPEG",
            b"\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C": "WMV/WMA/ASF",
            b"\x1B\x4C\x00\x00": "SYS/COM",
            b"\x1F\x9D": "Z/TGZ",
            b"\x04\x22\x4D\x18": "MDF",
            b"\x53\x49\x4D\x50\x4C\x45": "SIMPLE TEXT",
            b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1": "MSI (Also DOC/XLS)",
            b"\x30\x82": "PEM/CER/DER (X.509)",
            b"\x20\x20\x20\x20": "TXT (Spaces)",
            b"\x7B\x22": "JSON",
            b"\x4C\x69\x73\x74": "Shell Script (LIST)",
        }

        with open(self.file_path, "rb") as f:
                file_header = f.read(64)

             # Check for WebP
                if file_header.startswith(b"\x52\x49\x46\x46") and file_header[8:12] == b"WEBP":
                    detected_type = "WebP"

        detected_type = "Unknown"
        for signature, filetype in magic_db.items():
                if file_header.startswith(signature):
                    detected_type = filetype
                    break
        
        declared_type = file_type.split("/")[-1].upper() if file_type != "UNKNOWN" else "UNKNOWN"
        status = "SPOOFED" if detected_type != declared_type and detected_type != "Unknown" else "Valid"
        
        self.analysis_results["magic"] = {
                "Detected Type": detected_type,
                "Declared Type": declared_type,
                "Status": status,
                "Extension": extension if extension else "None"
            }


    def entropy_analysis(self):
        with open(self.file_path, "rb") as f:
            data = f.read()
        
        if not data:
            return
        
        byte_counts = Counter(data)
        length = len(data)
        entropy = -sum((count / length) * math.log2(count / length) for count in byte_counts.values() if count > 0)
        
        lsb_suspicious = False
        if entropy > 7.8 and self.analysis_results.get("magic", {}).get("Detected Type") in ["PNG", "JPEG"]:
            lsb_suspicious = True
        
        self.analysis_results["entropy"] = {
            "Entropy": round(entropy, 2),
            "LSB Check": "Hidden bits suspected" if lsb_suspicious else "No hidden bits detected"
        }

    def header_spoof_check(self):
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
        
        spoof_detected = is_pe and self.analysis_results["magic"]["Declared Type"] not in ["EXE", "DLL"]
        
        self.analysis_results["spoof"] = {
            "Spoof Detected": "Yes" if spoof_detected else "No",
            "Details": "Mismatched PE header" if spoof_detected else "Header consistent"
        }

    def byte_pattern_analysis(self):
        with open(self.file_path, "rb") as f:
            data = f.read(1024)
        
        bigrams = Counter(zip(data, data[1:]))
        total = sum(bigrams.values())
        if total == 0:
            return
        
        exe_bigrams = {(0x4D, 0x5A): 0.1, (0x50, 0x45): 0.05}
        similarity = sum(min(bigrams.get(k, 0) / total, v) for k, v in exe_bigrams.items()) / sum(exe_bigrams.values())
        
        self.analysis_results["pattern"] = {
            "Similarity to EXE": f"{int(similarity * 100)}% match to known EXE"
        }

    def structure_validation(self):
        valid = True
        details = "Structure valid"
        
        if self.analysis_results["magic"]["Detected Type"] == "ZIP":
            with open(self.file_path, "rb") as f:
                data = f.read()
                if not data.endswith(b"\x50\x4B\x05\x06"):
                    valid = False
                    details = "Invalid ZIP end of central directory"
        
        self.analysis_results["structure"] = {
            "Valid": "Yes" if valid else "No",
            "Details": details
        }

    def display_results(self):
        output = "FileScope Analysis Results\n" + "="*30 + "\n"
        output += f"File: {os.path.basename(self.file_path)}\n"
        output += f"Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M IST')}\n\n"
        output += "[SUMMARY]\n"
        output += f"Detected Type: {self.analysis_results['magic']['Detected Type']}\n"
        output += f"Declared Type: {self.analysis_results['magic']['Declared Type']}\n"
        output += f"Status: {self.analysis_results['magic']['Status']}\n"
        output += f"Risk Level: {'HIGH' if self.analysis_results['magic']['Status'] == 'SPOOFED' else 'LOW'}\n\n"
        
        output += "[DETAILS]\n"
        output += f"- Magic Number: {self.analysis_results['magic']['Detected Type']}\n"
        output += f"- Extension: {self.analysis_results['magic']['Extension']}\n"
        output += f"- Structure Validity: {self.analysis_results['structure']['Valid']} ({self.analysis_results['structure']['Details']})\n"
        output += f"- Entropy Analysis: {self.analysis_results['entropy']['Entropy']} ({self.analysis_results['entropy']['LSB Check']})\n"
        output += f"- Spoof Check: {self.analysis_results['spoof']['Spoof Detected']} ({self.analysis_results['spoof']['Details']})\n"
        output += f"- Byte Pattern Similarity: {self.analysis_results['pattern']['Similarity to EXE']}\n"
        
        output += "\n[RECOMMENDATION]\n"
        output += "Quarantine the file immediately. DO NOT run on production systems." if self.analysis_results["magic"]["Status"] == "SPOOFED" else "File appears safe but verify before execution."
        
        self.output_text.insert(tk.END, output)

    def plot_entropy(self):
        with open(self.file_path, "rb") as f:
            data = f.read(1024)
        
        if not data:
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
        
        for i, entropy in enumerate(entropies):
            height = (entropy / 8) * 80
            self.entropy_canvas.create_rectangle(i*10, 100-height, (i+1)*10, 100, fill="blue")

    def export_pdf(self):
        if not self.file_path or not self.analysis_results:
            messagebox.showwarning("Warning", "No analysis results to export!")
            return
        
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

if __name__ == "__main__":
    root = TkinterDnD.Tk()  # Drag-and-drop enabled root
    app = FileScope(root)
    root.mainloop()
