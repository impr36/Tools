import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinterdnd2 import TkinterDnD, DND_FILES
from PIL import Image, ImageTk
import cv2
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class StegoAnalysisRedesigned:
    def __init__(self, root):
        self.root = root
        self.root.title("🕵️ Steganography Analysis Tool")
        self.root.geometry("1200x800")
        self.root.configure(bg="#f8c5c5")  # Light pink background
        self.image = None
        self.image_path = None
        self.original_image = None
        self.tk_img = None
        self.uploaded_img_label = None
        self.create_layout()

    def create_layout(self):
        # ----- Scrollable canvas setup -----
        container = tk.Frame(self.root)
        container.pack(fill="both", expand=True)
    
        canvas = tk.Canvas(container, bg="#f8c5c5", highlightthickness=0)
        scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview)
        
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
        self.scrollable_frame = tk.Frame(canvas, bg="#f8c5c5")
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
    
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
    
        # ----- Cross-platform mouse scroll -----
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
    
        def _on_linux_scroll(event):
            canvas.yview_scroll(-1 if event.num == 4 else 1, "units")
    
        self.scrollable_frame.bind_all("<MouseWheel>", _on_mousewheel)   # Windows/macOS
        self.scrollable_frame.bind_all("<Button-4>", _on_linux_scroll)   # Linux scroll up
        self.scrollable_frame.bind_all("<Button-5>", _on_linux_scroll)   # Linux scroll down
    
        # Optional: handle resizing if you have defined on_resize()
        if hasattr(self, 'on_resize'):
            self.root.bind("<Configure>", self.on_resize)


        # ---------- TOP FRAME ----------
        top_frame = tk.Frame(self.scrollable_frame, bg="#f8c5c5")
        top_frame.pack(fill="x", padx=20, pady=(15, 5))

        self.upload_frame = tk.Label(top_frame, text="Upload Image\n(Drag-&-Drop here)", bg="#cce6f7",fg="black", font=("Helvetica", 12, "bold"),
                              relief="ridge", bd=3, width=90, height=15, justify="center", anchor="center")
        self.upload_frame.pack(side="left", padx=10, pady=10)
        self.upload_frame.drop_target_register(DND_FILES)
        self.upload_frame.dnd_bind('<<Drop>>', self.drop_image)

        buttons_frame = tk.Frame(top_frame, bg="#f8c5c5")
        buttons_frame.pack(side="right", padx=10, pady=20)
        
        button_style = {
            "font": ("Helvetica", 12, "bold"),
            "background": "#4CAF50",  # Green color
            "foreground": "white",
            "activebackground": "#45a049",
            "activeforeground": "white",
            "bd": 3,
            "relief": "raised",
            "width": 18,
            "height": 2
        }
        
        new_btn = tk.Button(buttons_frame, text="+ New Image", command=self.load_image, **button_style)
        remove_btn = tk.Button(buttons_frame, text="🗑 Remove", command=self.clear_image, **button_style)
        
        new_btn.pack(pady=10, padx=10, fill="x")
        remove_btn.pack(pady=10, padx=10, fill="x")

        # ---------- MIDDLE FRAME ----------
        middle_frame = tk.Frame(self.scrollable_frame, bg="#f8c5c5")
        middle_frame.pack(fill="both", expand=True, padx=20, pady=(5, 10))

        left_frame = tk.Frame(middle_frame, bg="#d3d3d3", width=350)
        left_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        self.result_text = tk.Text(left_frame, font=("Helvetica", 10), wrap=tk.WORD)
        self.result_text.pack(side="left", fill="both", expand=True, padx=(5, 0), pady=5)

        scrollbar = tk.Scrollbar(left_frame, command=self.result_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.result_text.config(yscrollcommand=scrollbar.set)

        right_frame = tk.Frame(middle_frame, bg="#f8c5c5")
        right_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        self.fig, self.ax = plt.subplots(figsize=(5, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, master=right_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, pady=5)

        # ---------- BUTTONS GRID ----------
        self.buttons_frame = tk.Frame(right_frame, bg="#f8c5c5")
        self.buttons_frame.pack(pady=(10, 5), fill="x")

        btn_style = {"bg": "#fff59d", "font": ("Helvetica", 10, "bold"), "width": 20, "height": 2}

        btn1 = tk.Button(self.buttons_frame, text="Noise Analysis", command=self.noise_analysis, **btn_style)
        btn2 = tk.Button(self.buttons_frame, text="Histogram Analysis", command=self.histogram_analysis, **btn_style)
        btn3 = tk.Button(self.buttons_frame, text="Chi-Square Test", command=self.chi_square, **btn_style)
        btn4 = tk.Button(self.buttons_frame, text="LSB Uniformity", command=self.lsb_uniformity, **btn_style)
        btn5 = tk.Button(self.buttons_frame, text="RS Analysis", command=self.rs_analysis, **btn_style)
        btn6 = tk.Button(self.buttons_frame, text="Full Analysis", command=self.run_all_analyses, **btn_style)

        btn1.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        btn2.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        btn3.grid(row=1, column=0, padx=5, pady=5, sticky="ew")
        btn4.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        btn5.grid(row=2, column=0, padx=5, pady=5, sticky="ew")
        btn6.grid(row=2, column=1, padx=5, pady=5, sticky="ew")

        self.buttons_frame.grid_columnconfigure(0, weight=1)
        self.buttons_frame.grid_columnconfigure(1, weight=1)

        # ---------- BOTTOM FRAME ----------
        bottom_frame = tk.Frame(self.scrollable_frame, bg="#f8c5c5")
        bottom_frame.pack(fill="x", padx=20, pady=(5, 15))

        gen_btn = tk.Button(bottom_frame, text="Generate Report", bg="#f08080", fg="white",
                            font=("Helvetica", 12, "bold"), width=25, height=2,
                            relief="raised", command=self.generate_report)
        gen_btn.pack(side="left", expand=True, padx=20, pady=10)

        down_btn = tk.Button(bottom_frame, text="Download", bg="#f08080", fg="white",
                             font=("Helvetica", 12, "bold"), width=25, height=2,
                             relief="raised", command=self.download_report)
        down_btn.pack(side="right", expand=True, padx=20, pady=10)

    def on_resize(self, event):
        self.root.update_idletasks()

    # -------- Image Logic ----------
    def drop_image(self, event):
        self.image_path = event.data.strip('{}')
        self.load_image(from_drop=True)

    def load_image(self, from_drop=False):
        if not from_drop:
            self.image_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png *.jpg *.jpeg *.bmp")])
        if self.image_path:
            try:
                img = Image.open(self.image_path).convert('RGB')
                self.image = np.array(img)

                # Convert to grayscale using PIL
                gray_img = img.convert("L").convert("RGB")  # convert back to RGB to match channels

                # Get size of upload frame
                self.upload_frame.update_idletasks()
                frame_width = self.upload_frame.winfo_width()
                frame_height = self.upload_frame.winfo_height()

                if frame_height <= 1 or frame_width <= 1:
                    self.upload_frame.update()
                    frame_width = self.upload_frame.winfo_width()
                    frame_height = self.upload_frame.winfo_height()

                # Resize both images to half of upload box width
                target_width = (frame_width - 20) // 2
                target_height = frame_height - 10

                img_resized = img.copy()
                gray_resized = gray_img.copy()
                img_resized.thumbnail((target_width, target_height))
                gray_resized.thumbnail((target_width, target_height))

                # Combine both images side by side
                combined_width = img_resized.width + gray_resized.width
                combined_height = max(img_resized.height, gray_resized.height)
                combined = Image.new("RGB", (combined_width, combined_height), (255, 255, 255))
                combined.paste(img_resized, (0, 0))
                combined.paste(gray_resized, (img_resized.width, 0))

                self.tk_img = ImageTk.PhotoImage(combined)

                # Show image in upload box
                if self.uploaded_img_label:
                    self.uploaded_img_label.config(image=self.tk_img, text="")
                else:
                    self.uploaded_img_label = tk.Label(self.upload_frame, image=self.tk_img, bg="#cce6f7")
                    self.uploaded_img_label.place(relx=0.5, rely=0.5, anchor="center")

                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"Loaded image: {self.image_path}\n")
                self.ax.clear()
                self.canvas.draw()

            except Exception as e:
                messagebox.showerror("Error", f"Could not load image: {str(e)}")



    def clear_image(self):
        self.image = None
        self.image_path = None
        self.result_text.delete(1.0, tk.END)
        self.ax.clear()
        self.canvas.draw()

        if self.uploaded_img_label:
            self.uploaded_img_label.destroy()
            self.uploaded_img_label = None

        # Reset the label text
        self.upload_frame.config(text="Upload Image\n(Drag-&-Drop here)")


    # -------- Analysis Methods ----------
    def to_gray(self, img):
        return cv2.cvtColor(img, cv2.COLOR_RGB2GRAY) if len(img.shape) == 3 else img

    def lsb_uniformity(self):
        if self.image is None: return
        gray = self.to_gray(self.image)
        lsb = gray & 1
        ratio = np.sum(lsb) / gray.size
        self.result_text.insert(tk.END, f"\nLSB Ratio: {ratio:.4f}\n")

    def chi_square(self):
        if self.image is None: return
        gray = self.to_gray(self.image)
        lsb = gray & 1
        observed = np.histogram(lsb, bins=[0, 1, 2])[0]
        expected = np.array([gray.size / 2, gray.size / 2])
        chi = np.sum((observed - expected) ** 2 / expected)
        self.result_text.insert(tk.END, f"\nChi-square value: {chi:.2f}\n")

    def histogram_analysis(self):
        if self.image is None: return
        gray = self.to_gray(self.image)
        self.ax.clear()
        self.ax.hist(gray.ravel(), bins=256, color="#4CAF50")
        self.ax.set_title("Histogram")
        self.canvas.draw()
        self.result_text.insert(tk.END, "\nHistogram Analysis Done.\n")

    def rs_analysis(self):
        if self.image is None: return
        gray = self.to_gray(self.image)
        smooth = lambda x: np.sum(np.abs(np.diff(x.astype(float))))
        flipped = gray ^ 1
        r1, r2 = smooth(gray), smooth(flipped)
        self.result_text.insert(tk.END, f"\nRS Smoothness:\nOriginal={r1:.2f}, Flipped={r2:.2f}\n")

    def noise_analysis(self):
        if self.image is None: return
        gray = self.to_gray(self.image)
        lap = cv2.Laplacian(gray, cv2.CV_64F)
        noise = np.std(lap)
        self.ax.clear()
        self.ax.hist(lap.ravel(), bins=256, color="gray")
        self.ax.set_title("Noise Distribution")
        self.canvas.draw()
        self.result_text.insert(tk.END, f"\nNoise Std Dev: {noise:.2f}\n")

    def run_all_analyses(self):
        self.lsb_uniformity()
        self.chi_square()
        self.histogram_analysis()
        self.rs_analysis()
        self.noise_analysis()    

    def generate_report(self):
        messagebox.showinfo("Report", "PDF generation coming soon!")

    def download_report(self):
        messagebox.showinfo("Download", "Download functionality coming soon!")

if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = StegoAnalysisRedesigned(root)
    root.mainloop()
