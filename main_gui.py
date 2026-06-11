import math
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import time
import csv
from PIL import Image, ImageTk
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

import kripto_stego_lib as ksl

try:
    import docx
    import PyPDF2
except ImportError:
    pass

class SkripsiGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Aplikasi Kriptografi dan Steganografi")
        self.geometry("960x1150")

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill='both', padx=10, pady=10)

        self.tab_kripto     = ttk.Frame(self.notebook)
        self.tab_stego      = ttk.Frame(self.notebook)
        self.tab_perbandingan = ttk.Frame(self.notebook)
        self.tab_batch        = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_kripto,       text="Kriptografi")
        self.notebook.add(self.tab_stego,        text="Steganografi")
        self.notebook.add(self.tab_perbandingan, text="Perbandingan RGB vs YCbCr")
        self.notebook.add(self.tab_batch,        text="Pengujian CER")

        self.setup_kripto_tab()
        self.setup_stego_tab()
        self.setup_perbandingan_tab()
        self.setup_batch_tab()

    # ==================== TAB KRIPTOGRAFI ====================
    def setup_kripto_tab(self):
        frame_input = ttk.LabelFrame(self.tab_kripto, text="Input Teks (Plaintext / Ciphertext)")
        frame_input.pack(fill="x", padx=10, pady=10)

        self.btn_browse_file = ttk.Button(frame_input, text="Pilih File (.txt, .docx, .pdf)", command=self.load_text_file)
        self.btn_browse_file.pack(pady=5)

        self.text_area = tk.Text(frame_input, height=12, wrap="word")
        self.text_area.pack(fill="x", padx=10, pady=5)

        frame_key = ttk.Frame(self.tab_kripto)
        frame_key.pack(fill="x", padx=10, pady=5)

        ttk.Label(frame_key, text="Passphrase (16 Karakter):").pack(side="left")
        self.entry_key = ttk.Entry(frame_key, width=30)
        self.entry_key.pack(side="left", padx=10)

        frame_action = ttk.Frame(self.tab_kripto)
        frame_action.pack(pady=20)

        self.btn_enkripsi = ttk.Button(frame_action, text="Enkripsi (AES)", command=self.proses_enkripsi)
        self.btn_enkripsi.pack(side="left", padx=10)

        self.btn_dekripsi = ttk.Button(frame_action, text="Dekripsi (AES)", command=self.proses_dekripsi)
        self.btn_dekripsi.pack(side="left", padx=10)

        # --- Frame Evaluasi Waktu Kriptografi ---
        frame_waktu = ttk.LabelFrame(self.tab_kripto, text="Evaluasi Kinerja Waktu")
        frame_waktu.pack(fill="x", padx=10, pady=10)

        # Baris waktu enkripsi
        frame_waktu_enc = ttk.Frame(frame_waktu)
        frame_waktu_enc.pack(fill="x", padx=10, pady=3)
        ttk.Label(frame_waktu_enc, text="Waktu Enkripsi  :", width=20, anchor="w").pack(side="left")
        self.lbl_waktu_enkripsi = ttk.Label(
            frame_waktu_enc, text="-", foreground="blue", font=("Arial", 10, "bold")
        )
        self.lbl_waktu_enkripsi.pack(side="left", padx=5)

        # Baris waktu dekripsi
        frame_waktu_dec = ttk.Frame(frame_waktu)
        frame_waktu_dec.pack(fill="x", padx=10, pady=3)
        ttk.Label(frame_waktu_dec, text="Waktu Dekripsi  :", width=20, anchor="w").pack(side="left")
        self.lbl_waktu_dekripsi = ttk.Label(
            frame_waktu_dec, text="-", foreground="blue", font=("Arial", 10, "bold")
        )
        self.lbl_waktu_dekripsi.pack(side="left", padx=5)

        # Baris ukuran data
        frame_ukuran = ttk.Frame(frame_waktu)
        frame_ukuran.pack(fill="x", padx=10, pady=3)
        ttk.Label(frame_ukuran, text="Ukuran Data     :", width=20, anchor="w").pack(side="left")
        self.lbl_ukuran_data = ttk.Label(
            frame_ukuran, text="-", foreground="purple", font=("Arial", 10)
        )
        self.lbl_ukuran_data.pack(side="left", padx=5)

        # --- Frame Tabel Payload Steganografi ---
        frame_payload_tbl = ttk.LabelFrame(self.tab_kripto, text="Payload Steganografi")
        frame_payload_tbl.pack(fill="x", padx=10, pady=10)

        columns = ("jml_karakter", "ukuran_plain", "blok_aes", "ukuran_cipher", "total_payload")
        self.tbl_payload = ttk.Treeview(
            frame_payload_tbl, columns=columns, show="headings", height=1
        )

        self.tbl_payload.heading("jml_karakter",  text="Jumlah Karakter")
        self.tbl_payload.heading("ukuran_plain",  text="Ukuran Plaintext (byte)")
        self.tbl_payload.heading("blok_aes",      text="Blok AES (blok)")
        self.tbl_payload.heading("ukuran_cipher", text="Ukuran Ciphertext (byte)")
        self.tbl_payload.heading("total_payload", text="Total Payload (byte)")

        for col in columns:
            self.tbl_payload.column(col, anchor="center", width=150)

        self.tbl_payload.pack(fill="x", padx=10, pady=5)

    def load_text_file(self):
        filepath = filedialog.askopenfilename(
            filetypes=[("Text/Doc/PDF", "*.txt *.docx *.pdf"), ("Semua File", "*.*")]
        )
        if not filepath: return
        ext = os.path.splitext(filepath)[1].lower()
        content = ""
        try:
            if ext == '.txt':
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
            elif ext == '.docx':
                doc = docx.Document(filepath)
                content = "\n".join([para.text for para in doc.paragraphs])
            elif ext == '.pdf':
                with open(filepath, 'rb') as f:
                    reader = PyPDF2.PdfReader(f)
                    for page in reader.pages:
                        content += page.extract_text() + "\n"
            self.text_area.delete("1.0", tk.END)
            self.text_area.insert(tk.END, content)
        except Exception as e:
            messagebox.showerror("Error", f"Gagal membaca file: {str(e)}")

    def proses_enkripsi(self):
        pesan = self.text_area.get("1.0", tk.END).strip()
        kunci = self.entry_key.get()
        if not pesan: return messagebox.showwarning("Peringatan", "Pesan tidak boleh kosong!")
        if len(kunci) == 0: return messagebox.showwarning("Peringatan", "Passphrase tidak boleh kosong!")
        try:
            ukuran_plain = len(pesan.encode('utf-8'))
            jumlah_karakter = len(pesan)
            start_time = time.perf_counter()
            cipherhex = ksl.aes_enkripsi(pesan, kunci)
            end_time = time.perf_counter()
            waktu_enkripsi = end_time - start_time

            self.text_area.delete("1.0", tk.END)
            self.text_area.insert(tk.END, cipherhex)

            # Hitung payload steganografi
            blok_aes = math.ceil(ukuran_plain / 16)
            ukuran_cipher = blok_aes * 16
            total_payload = ukuran_cipher + 4  # +4 byte header 32-bit steganografi

            # Update tabel payload
            for item in self.tbl_payload.get_children():
                self.tbl_payload.delete(item)
            self.tbl_payload.insert("", "end", values=(
                jumlah_karakter,
                ukuran_plain,
                blok_aes,
                ukuran_cipher,
                total_payload
            ))

            # Tampilkan waktu enkripsi
            waktu_str = f"{waktu_enkripsi:.6f} detik"
            self.lbl_waktu_enkripsi.config(text=waktu_str)
            self.lbl_ukuran_data.config(
                text=f"Plaintext: {ukuran_plain} byte  |  Ciphertext: {ukuran_cipher} byte ({len(cipherhex)} hex chars)"
            )

            messagebox.showinfo(
                "Sukses",
                f"Teks berhasil dienkripsi!\n\n"
                f"Waktu Enkripsi: {waktu_str}\n"
                f"Ukuran Plaintext: {ukuran_plain} byte\n"
                f"Blok AES: {blok_aes} blok\n"
                f"Ukuran Ciphertext: {ukuran_cipher} byte\n"
                f"Total Payload Steganografi: {total_payload} byte"
            )
        except Exception as e:
            messagebox.showerror("Error", f"Terjadi kesalahan enkripsi: {str(e)}")

    def proses_dekripsi(self):
        cipherhex = self.text_area.get("1.0", tk.END).strip()
        kunci = self.entry_key.get()
        if not cipherhex: return messagebox.showwarning("Peringatan", "Ciphertext tidak boleh kosong!")
        try:
            ukuran_cipher = len(cipherhex)
            start_time = time.perf_counter()
            plaintext = ksl.aes_dekripsi(cipherhex, kunci)
            end_time = time.perf_counter()
            waktu_dekripsi = end_time - start_time

            self.text_area.delete("1.0", tk.END)
            self.text_area.insert(tk.END, plaintext)

            # Tampilkan waktu dekripsi
            waktu_str = f"{waktu_dekripsi:.6f} detik"
            self.lbl_waktu_dekripsi.config(text=waktu_str)
            self.lbl_ukuran_data.config(
                text=f"Ciphertext: {ukuran_cipher} hex chars ({ukuran_cipher//2} byte)  |  Plaintext: {len(plaintext.encode('utf-8'))} byte"
            )

            messagebox.showinfo(
                "Sukses",
                f"Teks berhasil didekripsi!\n\n"
                f"Waktu Dekripsi: {waktu_str}\n"
                f"Ukuran Ciphertext: {ukuran_cipher//2} byte\n"
                f"Ukuran Plaintext: {len(plaintext.encode('utf-8'))} byte"
            )
        except Exception as e:
            messagebox.showerror("Error", f"Terjadi kesalahan dekripsi: {str(e)}")

    # ==================== TAB STEGANOGRAFI ====================
    def setup_stego_tab(self):
        # --- Scrollable wrapper ---
        stego_canvas = tk.Canvas(self.tab_stego, highlightthickness=0)
        stego_scrollbar = ttk.Scrollbar(self.tab_stego, orient="vertical", command=stego_canvas.yview)
        stego_inner = ttk.Frame(stego_canvas)

        stego_inner.bind(
            "<Configure>",
            lambda e: stego_canvas.configure(scrollregion=stego_canvas.bbox("all"))
        )
        stego_canvas.create_window((0, 0), window=stego_inner, anchor="nw")
        stego_canvas.configure(yscrollcommand=stego_scrollbar.set)

        stego_scrollbar.pack(side="right", fill="y")
        stego_canvas.pack(side="left", fill="both", expand=True)

        # Bind mousewheel untuk scroll
        def _on_mousewheel(event):
            stego_canvas.yview_scroll(int(-1*(event.delta/120)), "units")

        stego_canvas.bind_all("<MouseWheel>", _on_mousewheel)

        # Bind canvas width agar inner frame mengikuti lebar canvas
        def _on_canvas_configure(event):
            stego_canvas.itemconfig(stego_canvas.find_all()[0], width=event.width)

        stego_canvas.bind("<Configure>", _on_canvas_configure)

        # --- Konfigurasi Steganografi (Pilih Gambar & Ruang Warna) ---
        frame_config = ttk.LabelFrame(stego_inner, text="Konfigurasi Steganografi")
        frame_config.pack(fill="x", padx=10, pady=5)

        # Sub-frame Kiri: Pilih Gambar
        frame_left = ttk.Frame(frame_config)
        frame_left.pack(side="left", fill="both", expand=True, padx=5, pady=5)

        self.lbl_image_path = ttk.Label(frame_left, text="Belum ada gambar yang dipilih", wraplength=400)
        self.lbl_image_path.pack(anchor="w", pady=2)

        self.btn_browse_img = ttk.Button(
            frame_left, text="Pilih Gambar (Cover / Stego)", command=self.load_image
        )
        self.btn_browse_img.pack(anchor="w", pady=2)

        # Sub-frame Kanan: Pilihan Ruang Warna
        frame_right = ttk.Frame(frame_config)
        frame_right.pack(side="right", padx=15, pady=5)

        ttk.Label(frame_right, text="Pilihan Ruang Warna:").pack(anchor="w", pady=2)
        self.colorspace_var = tk.StringVar(value="RGB")
        rb_rgb = ttk.Radiobutton(frame_right, text="RGB (Langsung)", variable=self.colorspace_var, value="RGB")
        rb_rgb.pack(anchor="w", pady=1)
        rb_ycbcr = ttk.Radiobutton(frame_right, text="YCbCr (Konversi)", variable=self.colorspace_var, value="YCbCr")
        rb_ycbcr.pack(anchor="w", pady=1)

        ttk.Separator(frame_right, orient="horizontal").pack(fill="x", pady=4)
        self.hex_mode_var = tk.BooleanVar(value=True)
        chk_hex = ttk.Checkbutton(
            frame_right, text="Ciphertext (Hex → Biner)",
            variable=self.hex_mode_var
        )
        chk_hex.pack(anchor="w", pady=1)
        ttk.Label(
            frame_right, text="Centang jika data adalah ciphertext hex",
            foreground="gray", font=("Arial", 7)
        ).pack(anchor="w")

        frame_preview = ttk.Frame(stego_inner)
        frame_preview.pack(fill="x", padx=10, pady=5)

        self.lbl_img_input = ttk.Label(
            frame_preview, text="Gambar Input", anchor="center",
            borderwidth=2, relief="groove", width=45
        )
        self.lbl_img_input.pack(side="left", padx=5, fill="both", expand=True)

        self.lbl_img_output = ttk.Label(
            frame_preview, text="Gambar Output (Stego)", anchor="center",
            borderwidth=2, relief="groove", width=45
        )
        self.lbl_img_output.pack(side="right", padx=5, fill="both", expand=True)

        frame_data = ttk.LabelFrame(
            stego_inner, text="Pesan Rahasia (Data untuk disisip / Hasil ekstrak)"
        )
        frame_data.pack(fill="x", padx=10, pady=5)

        self.stego_text_area = tk.Text(frame_data, height=4, wrap="word")
        self.stego_text_area.pack(fill="x", padx=10, pady=5)

        # --- Tombol Aksi (di atas, agar selalu terlihat) ---
        frame_action = ttk.Frame(stego_inner)
        frame_action.pack(pady=8)

        self.btn_sisipkan = ttk.Button(
            frame_action, text="Sisipkan ke Gambar (DCT)", command=self.proses_sisipkan
        )
        self.btn_sisipkan.pack(side="left", padx=10)

        self.btn_ekstrak = ttk.Button(
            frame_action, text="Ekstrak dari Gambar (DCT)", command=self.proses_ekstrak
        )
        self.btn_ekstrak.pack(side="left", padx=10)

        # --- Frame Payload Steganografi ---
        frame_payload = ttk.LabelFrame(
            stego_inner, text="Informasi Payload Steganografi"
        )
        frame_payload.pack(fill="x", padx=10, pady=5)

        # Baris ukuran pesan
        frame_msg_size = ttk.Frame(frame_payload)
        frame_msg_size.pack(fill="x", padx=10, pady=3)
        ttk.Label(frame_msg_size, text="Ukuran Pesan    :", width=20, anchor="w").pack(side="left")
        self.lbl_payload_msg = ttk.Label(
            frame_msg_size, text="-", foreground="blue", font=("Arial", 10, "bold")
        )
        self.lbl_payload_msg.pack(side="left", padx=5)

        # Baris kapasitas gambar
        frame_cap = ttk.Frame(frame_payload)
        frame_cap.pack(fill="x", padx=10, pady=3)
        ttk.Label(frame_cap, text="Kapasitas Gambar :", width=20, anchor="w").pack(side="left")
        self.lbl_payload_cap = ttk.Label(
            frame_cap, text="-", foreground="green", font=("Arial", 10, "bold")
        )
        self.lbl_payload_cap.pack(side="left", padx=5)

        # Baris utilisasi
        frame_util = ttk.Frame(frame_payload)
        frame_util.pack(fill="x", padx=10, pady=3)
        ttk.Label(frame_util, text="Utilisasi Payload :", width=20, anchor="w").pack(side="left")
        self.lbl_payload_util = ttk.Label(
            frame_util, text="-", foreground="purple", font=("Arial", 10, "bold")
        )
        self.lbl_payload_util.pack(side="left", padx=5)
        ttk.Label(
            frame_util,
            text="(Persentase kapasitas yang digunakan)",
            foreground="gray"
        ).pack(side="left", padx=10)

        # Baris waktu sisip
        frame_waktu_sisip = ttk.Frame(frame_payload)
        frame_waktu_sisip.pack(fill="x", padx=10, pady=3)
        ttk.Label(frame_waktu_sisip, text="Waktu Penyisipan :", width=20, anchor="w").pack(side="left")
        self.lbl_waktu_sisip = ttk.Label(
            frame_waktu_sisip, text="-", foreground="#D35400", font=("Arial", 10, "bold")
        )
        self.lbl_waktu_sisip.pack(side="left", padx=5)

        # Baris waktu ekstrak
        frame_waktu_eks = ttk.Frame(frame_payload)
        frame_waktu_eks.pack(fill="x", padx=10, pady=3)
        ttk.Label(frame_waktu_eks, text="Waktu Ekstraksi  :", width=20, anchor="w").pack(side="left")
        self.lbl_waktu_ekstrak = ttk.Label(
            frame_waktu_eks, text="-", foreground="#D35400", font=("Arial", 10, "bold")
        )
        self.lbl_waktu_ekstrak.pack(side="left", padx=5)

        # --- Frame Hasil MSE & PSNR (Steganografi) ---
        frame_metrics = ttk.LabelFrame(
            stego_inner, text="Hasil Pengukuran Kualitas Gambar (MSE & PSNR)"
        )
        frame_metrics.pack(fill="x", padx=10, pady=5)

        # Baris label MSE
        frame_mse_row = ttk.Frame(frame_metrics)
        frame_mse_row.pack(fill="x", padx=10, pady=3)
        ttk.Label(frame_mse_row, text="MSE  :", width=10, anchor="w").pack(side="left")
        self.lbl_mse_value = ttk.Label(
            frame_mse_row, text="-", foreground="blue", font=("Arial", 10, "bold")
        )
        self.lbl_mse_value.pack(side="left", padx=5)
        ttk.Label(
            frame_mse_row,
            text="(Semakin kecil semakin baik. Ideal: mendekati 0)",
            foreground="gray"
        ).pack(side="left", padx=10)

        # Baris label PSNR
        frame_psnr_row = ttk.Frame(frame_metrics)
        frame_psnr_row.pack(fill="x", padx=10, pady=3)
        ttk.Label(frame_psnr_row, text="PSNR :", width=10, anchor="w").pack(side="left")
        self.lbl_psnr_value = ttk.Label(
            frame_psnr_row, text="-", foreground="green", font=("Arial", 10, "bold")
        )
        self.lbl_psnr_value.pack(side="left", padx=5)
        ttk.Label(
            frame_psnr_row,
            text="(Semakin tinggi semakin baik. Ideal: > 40 dB)",
            foreground="gray"
        ).pack(side="left", padx=10)

        # Baris label per-channel
        frame_channel_row = ttk.Frame(frame_metrics)
        frame_channel_row.pack(fill="x", padx=10, pady=3)
        ttk.Label(frame_channel_row, text="Per-Channel:", width=12, anchor="w").pack(side="left")
        self.lbl_channel_value = ttk.Label(frame_channel_row, text="-", foreground="purple")
        self.lbl_channel_value.pack(side="left", padx=5)
        # -----------------------------------------------

        self.image_path = None

    def tampilkan_gambar(self, filepath, label_widget):
        try:
            img_pil = Image.open(filepath)
            img_pil.thumbnail((250, 250))
            photo = ImageTk.PhotoImage(img_pil)
            label_widget.config(image=photo, text="")
            label_widget.image = photo
        except Exception as e:
            print(f"Gagal memuat gambar untuk preview: {str(e)}")

    def load_image(self):
        filepath = filedialog.askopenfilename(filetypes=[("PNG Images", "*.png")])
        if filepath:
            self.image_path = filepath
            self.lbl_image_path.config(text=filepath)
            self.lbl_img_input.config(image='', text="Gambar Input")
            self.lbl_img_output.config(image='', text="Gambar Output (Stego)")
            self.lbl_mse_value.config(text="-")
            self.lbl_psnr_value.config(text="-")
            self.lbl_channel_value.config(text="-")
            self.lbl_payload_msg.config(text="-")
            self.lbl_payload_cap.config(text="-")
            self.lbl_payload_util.config(text="-")
            self.lbl_waktu_sisip.config(text="-")
            self.lbl_waktu_ekstrak.config(text="-")
            self.tampilkan_gambar(filepath, self.lbl_img_input)

    def proses_sisipkan(self):
        if not self.image_path:
            return messagebox.showwarning("Peringatan", "Pilih gambar Cover PNG terlebih dahulu!")
        pesan = self.stego_text_area.get("1.0", tk.END).strip()
        if not pesan:
            return messagebox.showwarning("Peringatan", "Pesan rahasia tidak boleh kosong!")

        base_path, _ = os.path.splitext(self.image_path)
        mode = self.colorspace_var.get()
        if mode == "YCbCr":
            stego_save_path = f"{base_path}Stego_YCbCr.png"
        else:
            stego_save_path = f"{base_path}Stego_RGB.png"

        try:
            # Konversi hex → binary jika hex mode aktif
            if self.hex_mode_var.get():
                try:
                    raw_bytes = bytes.fromhex(pesan)
                    pesan_to_embed = raw_bytes.decode('latin-1')
                except ValueError:
                    return messagebox.showerror(
                        "Error",
                        "Data bukan hex string yang valid!\n"
                        "Matikan opsi 'Ciphertext (Hex → Biner)' jika ingin menyisipkan teks biasa."
                    )
            else:
                pesan_to_embed = pesan

            # Proses penyisipan berdasarkan pilihan ruang warna (dengan timing)
            start_time = time.perf_counter()
            if mode == "YCbCr":
                payload_info = ksl.sisipkan_stego_ycbcr(self.image_path, stego_save_path, pesan_to_embed)
            else:
                payload_info = ksl.sisipkan_stego(self.image_path, stego_save_path, pesan_to_embed)
            end_time = time.perf_counter()
            waktu_sisip = end_time - start_time

            # Tampilkan gambar stego
            self.tampilkan_gambar(stego_save_path, self.lbl_img_output)

            # Tampilkan informasi payload
            self.lbl_payload_msg.config(
                text=f"{payload_info['message_bytes']} byte ({payload_info['message_bits']} bit)"
            )
            self.lbl_payload_cap.config(
                text=f"{payload_info['capacity_bytes']} byte ({payload_info['capacity_bits']} bit)"
            )

            util_pct = payload_info['utilization_pct']
            if util_pct > 80:
                util_color = "red"
            elif util_pct > 50:
                util_color = "orange"
            else:
                util_color = "green"
            self.lbl_payload_util.config(
                text=f"{util_pct:.2f}%",
                foreground=util_color
            )

            # Tampilkan waktu penyisipan
            waktu_sisip_str = f"{waktu_sisip:.6f} detik"
            self.lbl_waktu_sisip.config(text=waktu_sisip_str)

            # Hitung MSE & PSNR
            mse, psnr = ksl.hitung_mse_psnr(self.image_path, stego_save_path)
            ch_results = ksl.hitung_mse_psnr_per_channel(self.image_path, stego_save_path)

            # Tampilkan di label
            self.lbl_mse_value.config(text=f"{mse:.6f}")

            if psnr == float('inf'):
                self.lbl_psnr_value.config(text="∞ dB (Gambar identik)")
            else:
                # Beri warna sesuai kualitas
                if psnr >= 40:
                    color = "green"
                elif psnr >= 30:
                    color = "orange"
                else:
                    color = "red"
                self.lbl_psnr_value.config(text=f"{psnr:.4f} dB", foreground=color)

            # Tampilkan per-channel
            ch_text = (
                f"R: MSE={ch_results['R']['mse']:.4f} PSNR={ch_results['R']['psnr']:.2f}dB  |  "
                f"G: MSE={ch_results['G']['mse']:.4f} PSNR={ch_results['G']['psnr']:.2f}dB  |  "
                f"B: MSE={ch_results['B']['mse']:.4f} PSNR={ch_results['B']['psnr']:.2f}dB"
            )
            self.lbl_channel_value.config(text=ch_text)

            messagebox.showinfo(
                "Sukses",
                f"Pesan berhasil disisipkan ({mode})!\n"
                f"Disimpan di:\n{stego_save_path}\n\n"
                f"--- Informasi Payload ---\n"
                f"Ukuran Pesan  : {payload_info['message_bytes']} byte ({payload_info['message_bits']} bit)\n"
                f"Kapasitas     : {payload_info['capacity_bytes']} byte ({payload_info['capacity_bits']} bit)\n"
                f"Utilisasi     : {util_pct:.2f}%\n"
                f"Waktu Sisip   : {waktu_sisip_str}\n\n"
                f"--- Hasil Pengukuran Kualitas ---\n"
                f"MSE  : {mse:.6f}\n"
                f"PSNR : {psnr:.4f} dB"
            )

        except Exception as e:
            messagebox.showerror("Error", f"Gagal menyisipkan: {str(e)}")

    def proses_ekstrak(self):
        if not self.image_path:
            return messagebox.showwarning("Peringatan", "Pilih gambar Stego PNG terlebih dahulu!")
        mode = self.colorspace_var.get()
        try:
            start_time = time.perf_counter()
            if mode == "YCbCr":
                hasil_ekstrak = ksl.ekstrak_stego_ycbcr(self.image_path)
            else:
                hasil_ekstrak = ksl.ekstrak_stego(self.image_path)
            end_time = time.perf_counter()
            waktu_ekstrak = end_time - start_time

            # Konversi binary → hex jika hex mode aktif
            if self.hex_mode_var.get():
                hasil_tampil = hasil_ekstrak.encode('latin-1').hex()
            else:
                hasil_tampil = hasil_ekstrak

            self.stego_text_area.delete("1.0", tk.END)
            self.stego_text_area.insert(tk.END, hasil_tampil)

            # Tampilkan waktu ekstraksi
            waktu_str = f"{waktu_ekstrak:.6f} detik"
            self.lbl_waktu_ekstrak.config(text=waktu_str)

            messagebox.showinfo(
                "Sukses",
                f"Pesan rahasia berhasil diekstrak menggunakan metode {mode}!\n\n"
                f"Waktu Ekstraksi: {waktu_str}\n"
                f"Ukuran Pesan: {len(hasil_tampil)} karakter"
            )
        except Exception as e:
            messagebox.showerror("Error", f"Gagal mengekstrak ({mode}): {str(e)}")

    # --- Metode CER Manual ---
    def cer_load_image(self):
        filepath = filedialog.askopenfilename(
            title="Pilih Gambar Stego (PNG)",
            filetypes=[("PNG Images", "*.png")]
        )
        if filepath:
            self.cer_image_path = filepath
            self.lbl_cer_img_path.config(text=filepath, foreground="black")

    def cer_load_message(self):
        filepath = filedialog.askopenfilename(
            title="Pilih File Plaintext Asli",
            filetypes=[("Text Files", "*.txt"), ("Semua File", "*.*")]
        )
        if filepath:
            self.cer_message_path = filepath
            self.lbl_cer_msg_path.config(text=filepath, foreground="black")

    def proses_cer_manual(self):
        if not self.cer_image_path:
            return messagebox.showwarning("Peringatan", "Pilih gambar stego (PNG) terlebih dahulu!")
        if not self.cer_message_path:
            return messagebox.showwarning("Peringatan", "Pilih file plaintext (.txt) terlebih dahulu!")

        kunci = self.cer_entry_key.get()
        if not kunci:
            return messagebox.showwarning("Peringatan", "Masukkan passphrase yang digunakan saat enkripsi!")

        try:
            # 1. Baca plaintext asli
            with open(self.cer_message_path, 'r', encoding='utf-8') as f:
                plaintext = f.read().strip()

            # 2. Enkripsi ulang plaintext dengan passphrase → ciphertext hex asli
            ciphertext_asli = ksl.aes_enkripsi(plaintext, kunci)

            # 3. Ekstrak pesan dari gambar stego
            mode = self.cer_mode_var.get()
            if mode == "YCbCr":
                pesan_ekstrak = ksl.ekstrak_stego_ycbcr(self.cer_image_path)
            else:
                pesan_ekstrak = ksl.ekstrak_stego(self.cer_image_path)

            # 4. Konversi hasil ekstraksi (binary) ke hex untuk perbandingan
            ciphertext_ekstrak = pesan_ekstrak.encode('latin-1').hex()

            # 5. Hitung CER: bandingkan ciphertext asli vs ciphertext yang diekstrak
            cer_val, err_count = self.hitung_cer(ciphertext_asli, ciphertext_ekstrak)

            # Tampilkan hasil
            if cer_val == 0.0:
                cer_color = "green"
                status_text = "✅ LULUS — Ciphertext berhasil diekstrak tanpa error"
                status_color = "green"
            elif cer_val < 10:
                cer_color = "orange"
                status_text = f"⚠️ GAGAL — Ada {err_count} karakter berbeda"
                status_color = "orange"
            else:
                cer_color = "red"
                status_text = f"❌ GAGAL — Ada {err_count} karakter berbeda (kerusakan besar)"
                status_color = "red"

            self.lbl_cer_result.config(text=f"{cer_val:.2f}%", foreground=cer_color)
            self.lbl_cer_error_count.config(text=f"{err_count} karakter")
            self.lbl_cer_orig_len.config(text=f"{len(ciphertext_asli)} karakter (hex)")
            self.lbl_cer_ext_len.config(text=f"{len(ciphertext_ekstrak)} karakter (hex)")
            self.lbl_cer_status.config(text=status_text, foreground=status_color)

            messagebox.showinfo(
                "Hasil CER Manual",
                f"Mode Ekstraksi: {mode}\n\n"
                f"CER: {cer_val:.2f}%\n"
                f"Jumlah Error: {err_count} karakter\n"
                f"Panjang Ciphertext Asli: {len(ciphertext_asli)} karakter (hex)\n"
                f"Panjang Ciphertext Ekstrak: {len(ciphertext_ekstrak)} karakter (hex)\n\n"
                f"Status: {status_text}"
            )

        except Exception as e:
            self.lbl_cer_result.config(text="ERROR", foreground="red")
            self.lbl_cer_error_count.config(text="-")
            self.lbl_cer_orig_len.config(text="-")
            self.lbl_cer_ext_len.config(text="-")
            self.lbl_cer_status.config(text=f"❌ Error: {str(e)}", foreground="red")
            messagebox.showerror("Error", f"Gagal menghitung CER: {str(e)}")

    # ==================== TAB PERBANDINGAN RGB vs YCbCr ====================
    def setup_perbandingan_tab(self):
        ttk.Label(
            self.tab_perbandingan,
            text="Bandingkan kualitas stego: Ruang Warna RGB (langsung) vs YCbCr (konversi)",
            font=("Arial", 10, "italic"), foreground="gray"
        ).pack(pady=8)

        frame_input = ttk.LabelFrame(self.tab_perbandingan, text="Pilih Gambar untuk Perbandingan")
        frame_input.pack(fill="x", padx=10, pady=5)

        # Baris 1: Pilih gambar cover (asli)
        frame_cover_row = ttk.Frame(frame_input)
        frame_cover_row.pack(fill="x", padx=10, pady=4)
        ttk.Label(frame_cover_row, text="Gambar Cover (Asli) :", width=28, anchor="w").pack(side="left")
        self.cmp_lbl_cover = ttk.Label(frame_cover_row, text="Belum dipilih", foreground="gray", wraplength=500)
        self.cmp_lbl_cover.pack(side="left", padx=5, fill="x", expand=True)
        ttk.Button(frame_cover_row, text="Pilih", command=self.cmp_load_cover).pack(side="right", padx=5)

        # Baris 2: Pilih gambar stego RGB
        frame_rgb_row = ttk.Frame(frame_input)
        frame_rgb_row.pack(fill="x", padx=10, pady=4)
        ttk.Label(frame_rgb_row, text="Gambar Stego RGB :", width=28, anchor="w").pack(side="left")
        self.cmp_lbl_stego_rgb = ttk.Label(frame_rgb_row, text="Belum dipilih", foreground="gray", wraplength=500)
        self.cmp_lbl_stego_rgb.pack(side="left", padx=5, fill="x", expand=True)
        ttk.Button(frame_rgb_row, text="Pilih", command=self.cmp_load_stego_rgb).pack(side="right", padx=5)

        # Baris 3: Pilih gambar stego YCbCr
        frame_ycbcr_row = ttk.Frame(frame_input)
        frame_ycbcr_row.pack(fill="x", padx=10, pady=4)
        ttk.Label(frame_ycbcr_row, text="Gambar Stego YCbCr :", width=28, anchor="w").pack(side="left")
        self.cmp_lbl_stego_ycbcr = ttk.Label(frame_ycbcr_row, text="Belum dipilih", foreground="gray", wraplength=500)
        self.cmp_lbl_stego_ycbcr.pack(side="left", padx=5, fill="x", expand=True)
        ttk.Button(frame_ycbcr_row, text="Pilih", command=self.cmp_load_stego_ycbcr).pack(side="right", padx=5)

        # Input pesan untuk verifikasi ekstraksi (opsional)
        frame_msg_row = ttk.Frame(frame_input)
        frame_msg_row.pack(fill="x", padx=10, pady=4)
        ttk.Label(frame_msg_row, text="Pesan Asli (untuk verifikasi) :", width=28, anchor="w").pack(side="left")
        self.cmp_entry_pesan = ttk.Entry(frame_msg_row, width=50)
        self.cmp_entry_pesan.pack(side="left", padx=5)
        ttk.Label(frame_msg_row, text="(opsional)", foreground="gray").pack(side="left")

        ttk.Button(
            self.tab_perbandingan,
            text="🔍  Jalankan Perbandingan RGB vs YCbCr",
            command=self.proses_perbandingan
        ).pack(pady=10)

        # --- Hasil Perbandingan: Dua kolom side-by-side ---
        frame_result = ttk.Frame(self.tab_perbandingan)
        frame_result.pack(fill="both", expand=True, padx=10, pady=5)

        # Kolom RGB
        self.frame_rgb = ttk.LabelFrame(frame_result, text="Metode RGB (Langsung)")
        self.frame_rgb.pack(side="left", fill="both", expand=True, padx=(0, 5))

        self.lbl_rgb_mse = ttk.Label(self.frame_rgb, text="MSE  : -", font=("Arial", 10))
        self.lbl_rgb_mse.pack(anchor="w", padx=10, pady=2)
        self.lbl_rgb_psnr = ttk.Label(self.frame_rgb, text="PSNR : -", font=("Arial", 10, "bold"))
        self.lbl_rgb_psnr.pack(anchor="w", padx=10, pady=2)
        self.lbl_rgb_channel = ttk.Label(self.frame_rgb, text="Per-Channel: -", font=("Arial", 9), wraplength=400)
        self.lbl_rgb_channel.pack(anchor="w", padx=10, pady=2)
        self.lbl_rgb_ekstrak = ttk.Label(self.frame_rgb, text="Ekstraksi: -", font=("Arial", 9))
        self.lbl_rgb_ekstrak.pack(anchor="w", padx=10, pady=2)
        self.lbl_rgb_path = ttk.Label(self.frame_rgb, text="Path: -", font=("Arial", 8), foreground="gray", wraplength=400)
        self.lbl_rgb_path.pack(anchor="w", padx=10, pady=2)

        # Kolom YCbCr
        self.frame_ycbcr = ttk.LabelFrame(frame_result, text="Metode YCbCr (Konversi)")
        self.frame_ycbcr.pack(side="right", fill="both", expand=True, padx=(5, 0))

        self.lbl_ycbcr_mse = ttk.Label(self.frame_ycbcr, text="MSE  : -", font=("Arial", 10))
        self.lbl_ycbcr_mse.pack(anchor="w", padx=10, pady=2)
        self.lbl_ycbcr_psnr = ttk.Label(self.frame_ycbcr, text="PSNR : -", font=("Arial", 10, "bold"))
        self.lbl_ycbcr_psnr.pack(anchor="w", padx=10, pady=2)
        self.lbl_ycbcr_channel = ttk.Label(self.frame_ycbcr, text="Per-Channel: -", font=("Arial", 9), wraplength=400)
        self.lbl_ycbcr_channel.pack(anchor="w", padx=10, pady=2)
        self.lbl_ycbcr_ekstrak = ttk.Label(self.frame_ycbcr, text="Ekstraksi: -", font=("Arial", 9))
        self.lbl_ycbcr_ekstrak.pack(anchor="w", padx=10, pady=2)
        self.lbl_ycbcr_path = ttk.Label(self.frame_ycbcr, text="Path: -", font=("Arial", 8), foreground="gray", wraplength=400)
        self.lbl_ycbcr_path.pack(anchor="w", padx=10, pady=2)

        # Kesimpulan
        frame_kesimpulan = ttk.LabelFrame(self.tab_perbandingan, text="Kesimpulan")
        frame_kesimpulan.pack(fill="x", padx=10, pady=5)
        self.lbl_kesimpulan = ttk.Label(
            frame_kesimpulan, text="Belum ada hasil perbandingan.",
            font=("Arial", 10), foreground="gray", wraplength=900
        )
        self.lbl_kesimpulan.pack(padx=10, pady=8)

        # Frame untuk Diagram Batang
        self.frame_chart = ttk.LabelFrame(self.tab_perbandingan, text="Diagram Batang Perbandingan")
        self.frame_chart.pack(fill="both", expand=True, padx=10, pady=5)
        self.chart_canvas = None  # Akan dibuat saat ada hasil

        # Inisialisasi path
        self.cmp_cover_path = None
        self.cmp_stego_rgb_path = None
        self.cmp_stego_ycbcr_path = None

    def cmp_load_cover(self):
        filepath = filedialog.askopenfilename(
            title="Pilih Gambar Cover (Asli)",
            filetypes=[("PNG Images", "*.png")]
        )
        if filepath:
            self.cmp_cover_path = filepath
            self.cmp_lbl_cover.config(text=filepath, foreground="black")

    def cmp_load_stego_rgb(self):
        filepath = filedialog.askopenfilename(
            title="Pilih Gambar Stego RGB",
            filetypes=[("PNG Images", "*.png")]
        )
        if filepath:
            self.cmp_stego_rgb_path = filepath
            self.cmp_lbl_stego_rgb.config(text=filepath, foreground="black")

    def cmp_load_stego_ycbcr(self):
        filepath = filedialog.askopenfilename(
            title="Pilih Gambar Stego YCbCr",
            filetypes=[("PNG Images", "*.png")]
        )
        if filepath:
            self.cmp_stego_ycbcr_path = filepath
            self.cmp_lbl_stego_ycbcr.config(text=filepath, foreground="black")

    def proses_perbandingan(self):
        if not self.cmp_cover_path:
            return messagebox.showwarning("Peringatan", "Pilih gambar Cover (Asli) terlebih dahulu!")
        if not self.cmp_stego_rgb_path:
            return messagebox.showwarning("Peringatan", "Pilih gambar Stego RGB terlebih dahulu!")
        if not self.cmp_stego_ycbcr_path:
            return messagebox.showwarning("Peringatan", "Pilih gambar Stego YCbCr terlebih dahulu!")

        pesan_asli = self.cmp_entry_pesan.get().strip()  # Opsional, untuk verifikasi

        # Reset labels
        self.lbl_rgb_mse.config(text="⏳ Memproses...")
        self.lbl_ycbcr_mse.config(text="⏳ Memproses...")
        self.lbl_kesimpulan.config(text="⏳ Sedang menghitung perbandingan...", foreground="gray")
        self.update_idletasks()

        try:
            # --- Hitung MSE & PSNR untuk RGB ---
            mse_rgb, psnr_rgb = ksl.hitung_mse_psnr(self.cmp_cover_path, self.cmp_stego_rgb_path)
            ch_rgb = ksl.hitung_mse_psnr_per_channel(self.cmp_cover_path, self.cmp_stego_rgb_path)

            # Coba ekstraksi RGB
            try:
                hasil_rgb = ksl.ekstrak_stego(self.cmp_stego_rgb_path)
                if pesan_asli:
                    rgb_ok = (hasil_rgb.strip() == pesan_asli)
                else:
                    rgb_ok = True  # Tidak ada pesan pembanding, anggap berhasil jika tidak error
            except Exception:
                hasil_rgb = "[GAGAL]"
                rgb_ok = False

            # --- Hitung MSE & PSNR untuk YCbCr ---
            mse_ycbcr, psnr_ycbcr = ksl.hitung_mse_psnr(self.cmp_cover_path, self.cmp_stego_ycbcr_path)
            ch_ycbcr = ksl.hitung_mse_psnr_per_channel(self.cmp_cover_path, self.cmp_stego_ycbcr_path)

            # Coba ekstraksi YCbCr
            try:
                hasil_ycbcr = ksl.ekstrak_stego_ycbcr(self.cmp_stego_ycbcr_path)
                if pesan_asli:
                    ycbcr_ok = (hasil_ycbcr.strip() == pesan_asli)
                else:
                    ycbcr_ok = True  # Tidak ada pesan pembanding, anggap berhasil jika tidak error
            except Exception:
                hasil_ycbcr = "[GAGAL]"
                ycbcr_ok = False

            def fmt_psnr(v):
                return "∞ dB (Identik)" if v == float('inf') else f"{v:.4f} dB"

            def psnr_color(v):
                if v == float('inf'):
                    return "green"
                elif v >= 40:
                    return "green"
                elif v >= 30:
                    return "orange"
                else:
                    return "red"

            # --- Tampilkan RGB ---
            self.lbl_rgb_mse.config(text=f"MSE  : {mse_rgb:.6f}")
            self.lbl_rgb_psnr.config(
                text=f"PSNR : {fmt_psnr(psnr_rgb)}",
                foreground=psnr_color(psnr_rgb)
            )
            self.lbl_rgb_channel.config(
                text=f"R: MSE={ch_rgb['R']['mse']:.4f} PSNR={ch_rgb['R']['psnr']:.2f}dB | "
                     f"G: MSE={ch_rgb['G']['mse']:.4f} PSNR={ch_rgb['G']['psnr']:.2f}dB | "
                     f"B: MSE={ch_rgb['B']['mse']:.4f} PSNR={ch_rgb['B']['psnr']:.2f}dB"
            )
            if pesan_asli:
                eks_rgb_text = "✅ BERHASIL" if rgb_ok else "❌ GAGAL"
                eks_rgb_color = "green" if rgb_ok else "red"
            else:
                if hasil_rgb != "[GAGAL]":
                    eks_rgb_text = f"✅ Terekstrak: \"{hasil_rgb[:50]}{'...' if len(hasil_rgb) > 50 else ''}\""
                    eks_rgb_color = "green"
                else:
                    eks_rgb_text = "❌ GAGAL mengekstrak"
                    eks_rgb_color = "red"
            self.lbl_rgb_ekstrak.config(text=f"Ekstraksi: {eks_rgb_text}", foreground=eks_rgb_color)
            self.lbl_rgb_path.config(text=f"Path: {self.cmp_stego_rgb_path}")

            # --- Tampilkan YCbCr ---
            self.lbl_ycbcr_mse.config(text=f"MSE  : {mse_ycbcr:.6f}")
            self.lbl_ycbcr_psnr.config(
                text=f"PSNR : {fmt_psnr(psnr_ycbcr)}",
                foreground=psnr_color(psnr_ycbcr)
            )
            self.lbl_ycbcr_channel.config(
                text=f"R: MSE={ch_ycbcr['R']['mse']:.4f} PSNR={ch_ycbcr['R']['psnr']:.2f}dB | "
                     f"G: MSE={ch_ycbcr['G']['mse']:.4f} PSNR={ch_ycbcr['G']['psnr']:.2f}dB | "
                     f"B: MSE={ch_ycbcr['B']['mse']:.4f} PSNR={ch_ycbcr['B']['psnr']:.2f}dB"
            )
            if pesan_asli:
                eks_ycbcr_text = "✅ BERHASIL" if ycbcr_ok else "❌ GAGAL"
                eks_ycbcr_color = "green" if ycbcr_ok else "red"
            else:
                if hasil_ycbcr != "[GAGAL]":
                    eks_ycbcr_text = f"✅ Terekstrak: \"{hasil_ycbcr[:50]}{'...' if len(hasil_ycbcr) > 50 else ''}\""
                    eks_ycbcr_color = "green"
                else:
                    eks_ycbcr_text = "❌ GAGAL mengekstrak"
                    eks_ycbcr_color = "red"
            self.lbl_ycbcr_ekstrak.config(text=f"Ekstraksi: {eks_ycbcr_text}", foreground=eks_ycbcr_color)
            self.lbl_ycbcr_path.config(text=f"Path: {self.cmp_stego_ycbcr_path}")

            # --- Kesimpulan ---
            rgb_psnr_val = psnr_rgb if psnr_rgb != float('inf') else 999
            ycbcr_psnr_val = psnr_ycbcr if psnr_ycbcr != float('inf') else 999

            if rgb_psnr_val > ycbcr_psnr_val:
                winner = "RGB (Langsung)"
                alasan = f"PSNR RGB ({fmt_psnr(psnr_rgb)}) lebih tinggi dari YCbCr ({fmt_psnr(psnr_ycbcr)})"
            elif ycbcr_psnr_val > rgb_psnr_val:
                winner = "YCbCr (Konversi)"
                alasan = f"PSNR YCbCr ({fmt_psnr(psnr_ycbcr)}) lebih tinggi dari RGB ({fmt_psnr(psnr_rgb)})"
            else:
                winner = "Sama"
                alasan = "Kedua metode menghasilkan PSNR yang sama"

            # Tambahan info ekstraksi
            if rgb_ok and not ycbcr_ok:
                eks_note = "⚠️ Metode YCbCr GAGAL mengekstrak pesan kembali."
            elif not rgb_ok and ycbcr_ok:
                eks_note = "⚠️ Metode RGB GAGAL mengekstrak pesan kembali."
            elif not rgb_ok and not ycbcr_ok:
                eks_note = "⚠️ Kedua metode GAGAL mengekstrak pesan."
            else:
                eks_note = "✅ Kedua metode berhasil mengekstrak pesan."

            self.lbl_kesimpulan.config(
                text=f"🏆 Metode Terbaik (PSNR): {winner}\n{alasan}\n{eks_note}",
                foreground="black"
            )

            # --- Tampilkan Diagram Batang ---
            self.tampilkan_diagram_batang(
                mse_rgb, psnr_rgb,
                mse_ycbcr, psnr_ycbcr
            )

            messagebox.showinfo(
                "Selesai",
                f"Perbandingan selesai!\n\n"
                f"[RGB]   MSE={mse_rgb:.6f}  |  PSNR={fmt_psnr(psnr_rgb)}  |  Ekstrak: {eks_rgb_text}\n"
                f"[YCbCr] MSE={mse_ycbcr:.6f}  |  PSNR={fmt_psnr(psnr_ycbcr)}  |  Ekstrak: {eks_ycbcr_text}\n\n"
                f"🏆 Metode terbaik: {winner}"
            )

        except Exception as e:
            self.lbl_rgb_mse.config(text="MSE  : -")
            self.lbl_ycbcr_mse.config(text="MSE  : -")
            self.lbl_kesimpulan.config(text=f"Error: {str(e)}", foreground="red")
            messagebox.showerror("Error", f"Terjadi kesalahan: {str(e)}")

    def tampilkan_diagram_batang(self, mse_rgb, psnr_rgb, mse_ycbcr, psnr_ycbcr):
        """Menampilkan diagram batang perbandingan MSE & PSNR di dalam frame_chart."""
        # Hapus chart sebelumnya jika ada
        if self.chart_canvas:
            self.chart_canvas.get_tk_widget().destroy()
            self.chart_canvas = None

        # Warna untuk masing-masing metode
        COLOR_RGB = '#4A90D9'      # Biru
        COLOR_YCBCR = '#E8734A'    # Oranye/Coral

        fig, axes = plt.subplots(1, 2, figsize=(9, 3.5), dpi=90)
        fig.patch.set_facecolor('#F5F5F5')
        fig.subplots_adjust(wspace=0.4, left=0.08, right=0.95, top=0.85, bottom=0.18)

        # --- Subplot 1: MSE Overall ---
        ax1 = axes[0]
        metode = ['RGB', 'YCbCr']
        mse_vals = [mse_rgb, mse_ycbcr]
        bars1 = ax1.bar(metode, mse_vals, color=[COLOR_RGB, COLOR_YCBCR], width=0.5, edgecolor='white', linewidth=1.2)
        ax1.set_title('MSE (Overall)', fontsize=10, fontweight='bold', pad=8)
        ax1.set_ylabel('Nilai MSE', fontsize=9)
        ax1.set_facecolor('#FAFAFA')
        ax1.grid(axis='y', alpha=0.3, linestyle='--')
        # Tambah ruang atas agar label tidak terpotong
        ax1.set_ylim(0, max(mse_vals) * 1.25)
        # Tampilkan nilai di atas bar
        for bar, val in zip(bars1, mse_vals):
            ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height(),
                     f'{val:.4f}', ha='center', va='bottom', fontsize=8, fontweight='bold')

        # --- Subplot 2: PSNR Overall ---
        ax2 = axes[1]
        psnr_rgb_disp = psnr_rgb if psnr_rgb != float('inf') else 100
        psnr_ycbcr_disp = psnr_ycbcr if psnr_ycbcr != float('inf') else 100
        psnr_vals = [psnr_rgb_disp, psnr_ycbcr_disp]
        bars2 = ax2.bar(metode, psnr_vals, color=[COLOR_RGB, COLOR_YCBCR], width=0.5, edgecolor='white', linewidth=1.2)
        ax2.set_title('PSNR (Overall)', fontsize=10, fontweight='bold', pad=8)
        ax2.set_ylabel('Nilai PSNR (dB)', fontsize=9)
        ax2.set_facecolor('#FAFAFA')
        ax2.grid(axis='y', alpha=0.3, linestyle='--')
        ax2.set_ylim(0, max(psnr_vals) * 1.18)
        # Label di atas bar
        labels_psnr = [
            '∞ dB' if psnr_rgb == float('inf') else f'{psnr_rgb:.2f} dB',
            '∞ dB' if psnr_ycbcr == float('inf') else f'{psnr_ycbcr:.2f} dB'
        ]
        for bar, lbl in zip(bars2, labels_psnr):
            ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height(),
                     lbl, ha='center', va='bottom', fontsize=8, fontweight='bold')

        # Embed chart ke tkinter
        self.chart_canvas = FigureCanvasTkAgg(fig, master=self.frame_chart)
        self.chart_canvas.draw()
        self.chart_canvas.get_tk_widget().pack(fill="both", expand=True, padx=5, pady=5)
        plt.close(fig)  # Tutup figure agar tidak bocor memori

    # ==================== TAB PENGUJIAN BATCH (CER) ====================
    def setup_batch_tab(self):
        # --- Scrollable wrapper ---
        batch_canvas = tk.Canvas(self.tab_batch, highlightthickness=0)
        batch_scrollbar = ttk.Scrollbar(self.tab_batch, orient="vertical", command=batch_canvas.yview)
        batch_inner = ttk.Frame(batch_canvas)

        batch_inner.bind(
            "<Configure>",
            lambda e: batch_canvas.configure(scrollregion=batch_canvas.bbox("all"))
        )
        batch_canvas.create_window((0, 0), window=batch_inner, anchor="nw")
        batch_canvas.configure(yscrollcommand=batch_scrollbar.set)

        batch_scrollbar.pack(side="right", fill="y")
        batch_canvas.pack(side="left", fill="both", expand=True)

        # Bind mousewheel untuk scroll
        def _on_mousewheel(event):
            batch_canvas.yview_scroll(int(-1*(event.delta/120)), "units")

        batch_canvas.bind_all("<MouseWheel>", _on_mousewheel)

        # Bind canvas width agar inner frame mengikuti lebar canvas
        def _on_canvas_configure(event):
            batch_canvas.itemconfig(batch_canvas.find_all()[0], width=event.width)

        batch_canvas.bind("<Configure>", _on_canvas_configure)

        self.batch_covers = []
        self.batch_texts = []

        frame_input = ttk.LabelFrame(batch_inner, text="Pemilihan File untuk Pengujian Batch")
        frame_input.pack(fill="x", padx=10, pady=5)

        # Baris Gambar Cover
        frame_cover = ttk.Frame(frame_input)
        frame_cover.pack(fill="x", padx=10, pady=5)
        ttk.Button(frame_cover, text="Pilih Gambar Cover (.png)", command=self.batch_load_covers, width=30).pack(side="left")
        self.lbl_batch_covers = ttk.Label(frame_cover, text="0 gambar terpilih", foreground="gray")
        self.lbl_batch_covers.pack(side="left", padx=10)

        # Baris File Teks
        frame_text = ttk.Frame(frame_input)
        frame_text.pack(fill="x", padx=10, pady=5)
        ttk.Button(frame_text, text="Pilih File Teks (.txt)", command=self.batch_load_texts, width=30).pack(side="left")
        self.lbl_batch_texts = ttk.Label(frame_text, text="0 file teks terpilih", foreground="gray")
        self.lbl_batch_texts.pack(side="left", padx=10)

        # Tombol Aksi
        frame_action = ttk.Frame(batch_inner)
        frame_action.pack(fill="x", padx=10, pady=5)
        ttk.Button(frame_action, text="▶ Jalankan Pengujian Batch", command=self.batch_run_tests).pack(side="left")
        ttk.Button(frame_action, text="💾 Ekspor Hasil ke CSV", command=self.batch_export_csv).pack(side="left", padx=10)

        self.progress_batch = ttk.Progressbar(batch_inner, orient="horizontal", mode="determinate")
        self.progress_batch.pack(fill="x", padx=10, pady=5)

        # Tabel Hasil
        frame_table = ttk.LabelFrame(batch_inner, text="Hasil Pengujian Batch")
        frame_table.pack(fill="both", expand=True, padx=10, pady=5)

        # Scrollbar untuk tabel
        scroll_y = ttk.Scrollbar(frame_table, orient="vertical")
        scroll_x = ttk.Scrollbar(frame_table, orient="horizontal")

        columns = ("cover", "payload_size", "mode", "cer", "error", "mse", "psnr", "waktu_sisip", "waktu_ekstrak", "status")
        self.tree_batch = ttk.Treeview(frame_table, columns=columns, show="headings",
                                       yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)

        scroll_y.config(command=self.tree_batch.yview)
        scroll_y.pack(side="right", fill="y")
        scroll_x.config(command=self.tree_batch.xview)
        scroll_x.pack(side="bottom", fill="x")

        self.tree_batch.heading("cover", text="Gambar Cover")
        self.tree_batch.heading("payload_size", text="Ukuran Pesan")
        self.tree_batch.heading("mode", text="Mode")
        self.tree_batch.heading("cer", text="CER (%)")
        self.tree_batch.heading("error", text="Error (char)")
        self.tree_batch.heading("mse", text="MSE")
        self.tree_batch.heading("psnr", text="PSNR (dB)")
        self.tree_batch.heading("waktu_sisip", text="Waktu Sisip (s)")
        self.tree_batch.heading("waktu_ekstrak", text="Waktu Ekstrak (s)")
        self.tree_batch.heading("status", text="Status")

        self.tree_batch.column("cover", width=120)
        self.tree_batch.column("payload_size", width=100, anchor="center")
        self.tree_batch.column("mode", width=80, anchor="center")
        self.tree_batch.column("cer", width=80, anchor="center")
        self.tree_batch.column("error", width=80, anchor="center")
        self.tree_batch.column("mse", width=80, anchor="center")
        self.tree_batch.column("psnr", width=80, anchor="center")
        self.tree_batch.column("waktu_sisip", width=100, anchor="center")
        self.tree_batch.column("waktu_ekstrak", width=110, anchor="center")
        self.tree_batch.column("status", width=80, anchor="center")

        self.tree_batch.pack(fill="both", expand=True)

        # --- Frame Pengujian CER Manual ---
        frame_cer = ttk.LabelFrame(
            batch_inner, text="Pengujian CER Manual"
        )
        frame_cer.pack(fill="x", padx=10, pady=5)

        ttk.Label(
            frame_cer,
            text="Pilih gambar stego yang sudah melalui kompresi JPEG lalu dikonversi ke PNG.\n",
            foreground="gray", font=("Arial", 8, "italic"), justify="left"
        ).pack(anchor="w", padx=10, pady=(5, 2))

        # Baris pilih gambar CER
        frame_cer_img = ttk.Frame(frame_cer)
        frame_cer_img.pack(fill="x", padx=10, pady=3)
        ttk.Label(frame_cer_img, text="Gambar Stego (PNG) :", width=22, anchor="w").pack(side="left")
        self.lbl_cer_img_path = ttk.Label(frame_cer_img, text="Belum dipilih", foreground="gray", wraplength=500)
        self.lbl_cer_img_path.pack(side="left", padx=5, fill="x", expand=True)
        ttk.Button(frame_cer_img, text="Pilih", command=self.cer_load_image).pack(side="right", padx=5)

        # Baris pilih file plaintext asli
        frame_cer_msg = ttk.Frame(frame_cer)
        frame_cer_msg.pack(fill="x", padx=10, pady=3)
        ttk.Label(frame_cer_msg, text="File Plaintext (.txt) :", width=22, anchor="w").pack(side="left")
        self.lbl_cer_msg_path = ttk.Label(frame_cer_msg, text="Belum dipilih", foreground="gray", wraplength=500)
        self.lbl_cer_msg_path.pack(side="left", padx=5, fill="x", expand=True)
        ttk.Button(frame_cer_msg, text="Pilih", command=self.cer_load_message).pack(side="right", padx=5)

        # Baris passphrase
        frame_cer_key = ttk.Frame(frame_cer)
        frame_cer_key.pack(fill="x", padx=10, pady=3)
        ttk.Label(frame_cer_key, text="Passphrase :", width=22, anchor="w").pack(side="left")
        self.cer_entry_key = ttk.Entry(frame_cer_key, width=30)
        self.cer_entry_key.pack(side="left", padx=5)
        ttk.Label(frame_cer_key, text="(sama dengan saat enkripsi)", foreground="gray", font=("Arial", 8)).pack(side="left", padx=5)

        # Pilihan ruang warna untuk ekstraksi CER
        frame_cer_mode = ttk.Frame(frame_cer)
        frame_cer_mode.pack(fill="x", padx=10, pady=3)
        ttk.Label(frame_cer_mode, text="Mode Ekstraksi :", width=22, anchor="w").pack(side="left")
        self.cer_mode_var = tk.StringVar(value="RGB")
        ttk.Radiobutton(frame_cer_mode, text="RGB", variable=self.cer_mode_var, value="RGB").pack(side="left", padx=5)
        ttk.Radiobutton(frame_cer_mode, text="YCbCr", variable=self.cer_mode_var, value="YCbCr").pack(side="left", padx=5)

        # Tombol hitung CER
        frame_cer_btn = ttk.Frame(frame_cer)
        frame_cer_btn.pack(pady=5)
        ttk.Button(frame_cer_btn, text="🔍 Hitung CER", command=self.proses_cer_manual).pack()

        # Hasil CER
        frame_cer_result = ttk.Frame(frame_cer)
        frame_cer_result.pack(fill="x", padx=10, pady=3)

        frame_cer_val = ttk.Frame(frame_cer_result)
        frame_cer_val.pack(fill="x", pady=2)
        ttk.Label(frame_cer_val, text="CER              :", width=22, anchor="w").pack(side="left")
        self.lbl_cer_result = ttk.Label(
            frame_cer_val, text="-", foreground="blue", font=("Arial", 10, "bold")
        )
        self.lbl_cer_result.pack(side="left", padx=5)

        frame_cer_err = ttk.Frame(frame_cer_result)
        frame_cer_err.pack(fill="x", pady=2)
        ttk.Label(frame_cer_err, text="Jumlah Error     :", width=22, anchor="w").pack(side="left")
        self.lbl_cer_error_count = ttk.Label(
            frame_cer_err, text="-", foreground="red", font=("Arial", 10, "bold")
        )
        self.lbl_cer_error_count.pack(side="left", padx=5)

        frame_cer_len = ttk.Frame(frame_cer_result)
        frame_cer_len.pack(fill="x", pady=2)
        ttk.Label(frame_cer_len, text="Panjang Asli     :", width=22, anchor="w").pack(side="left")
        self.lbl_cer_orig_len = ttk.Label(
            frame_cer_len, text="-", foreground="purple", font=("Arial", 10)
        )
        self.lbl_cer_orig_len.pack(side="left", padx=5)

        frame_cer_len2 = ttk.Frame(frame_cer_result)
        frame_cer_len2.pack(fill="x", pady=2)
        ttk.Label(frame_cer_len2, text="Panjang Ekstrak  :", width=22, anchor="w").pack(side="left")
        self.lbl_cer_ext_len = ttk.Label(
            frame_cer_len2, text="-", foreground="purple", font=("Arial", 10)
        )
        self.lbl_cer_ext_len.pack(side="left", padx=5)

        frame_cer_status = ttk.Frame(frame_cer_result)
        frame_cer_status.pack(fill="x", pady=(2, 8))
        ttk.Label(frame_cer_status, text="Status           :", width=22, anchor="w").pack(side="left")
        self.lbl_cer_status = ttk.Label(
            frame_cer_status, text="-", foreground="gray", font=("Arial", 10, "bold")
        )
        self.lbl_cer_status.pack(side="left", padx=5)

        # Inisialisasi path CER
        self.cer_image_path = None
        self.cer_message_path = None

        # --- Frame Uji Ketahanan Noise Salt & Pepper ---
        frame_noise = ttk.LabelFrame(
            batch_inner, text="Uji Ketahanan Noise Salt & Pepper"
        )
        frame_noise.pack(fill="x", padx=10, pady=5)

        ttk.Label(
            frame_noise,
            text="Menguji ketahanan pesan steganografi terhadap noise Salt & Pepper.\n",
            foreground="gray", font=("Arial", 8, "italic"), justify="left"
        ).pack(anchor="w", padx=10, pady=(5, 2))

        # Baris pilih gambar cover
        frame_noise_img = ttk.Frame(frame_noise)
        frame_noise_img.pack(fill="x", padx=10, pady=3)
        ttk.Label(frame_noise_img, text="Gambar Asli (Cover) :", width=22, anchor="w").pack(side="left")
        self.lbl_noise_img_path = ttk.Label(frame_noise_img, text="Belum dipilih", foreground="gray", wraplength=500)
        self.lbl_noise_img_path.pack(side="left", padx=5, fill="x", expand=True)
        ttk.Button(frame_noise_img, text="Pilih", command=self.noise_load_cover).pack(side="right", padx=5)

        # Baris pilih file plaintext asli
        frame_noise_msg = ttk.Frame(frame_noise)
        frame_noise_msg.pack(fill="x", padx=10, pady=3)
        ttk.Label(frame_noise_msg, text="File Plaintext (.txt) :", width=22, anchor="w").pack(side="left")
        self.lbl_noise_msg_path = ttk.Label(frame_noise_msg, text="Belum dipilih", foreground="gray", wraplength=500)
        self.lbl_noise_msg_path.pack(side="left", padx=5, fill="x", expand=True)
        ttk.Button(frame_noise_msg, text="Pilih", command=self.noise_load_message).pack(side="right", padx=5)

        # Baris passphrase noise
        frame_noise_key = ttk.Frame(frame_noise)
        frame_noise_key.pack(fill="x", padx=10, pady=3)
        ttk.Label(frame_noise_key, text="Passphrase :", width=22, anchor="w").pack(side="left")
        self.noise_entry_key = ttk.Entry(frame_noise_key, width=30)
        self.noise_entry_key.pack(side="left", padx=5)
        ttk.Label(frame_noise_key, text="(sama dengan saat enkripsi)", foreground="gray", font=("Arial", 8)).pack(side="left", padx=5)

        # Baris probabilitas noise
        frame_noise_prob = ttk.Frame(frame_noise)
        frame_noise_prob.pack(fill="x", padx=10, pady=3)
        ttk.Label(frame_noise_prob, text="Probabilitas Noise (%) :", width=22, anchor="w").pack(side="left")
        self.noise_entry_prob = ttk.Entry(frame_noise_prob, width=15)
        self.noise_entry_prob.insert(0, "0.001")
        self.noise_entry_prob.pack(side="left", padx=5)
        ttk.Label(frame_noise_prob, text="%", foreground="gray", font=("Arial", 8)).pack(side="left", padx=5)

        # Tombol jalankan uji ketahanan
        frame_noise_btn = ttk.Frame(frame_noise)
        frame_noise_btn.pack(pady=5)
        ttk.Button(frame_noise_btn, text="🔊 Jalankan Uji Ketahanan Noise (RGB & YCbCr)", command=self.proses_noise_test).pack()

        # Preview gambar
        frame_noise_preview = ttk.Frame(frame_noise)
        frame_noise_preview.pack(fill="x", padx=10, pady=5)

        self.lbl_noise_img_asli = ttk.Label(
            frame_noise_preview, text="Gambar Asli", anchor="center",
            borderwidth=2, relief="groove", width=30
        )
        self.lbl_noise_img_asli.pack(side="left", padx=5, fill="both", expand=True)

        self.lbl_noise_img_noised_rgb = ttk.Label(
            frame_noise_preview, text="Noised RGB", anchor="center",
            borderwidth=2, relief="groove", width=30
        )
        self.lbl_noise_img_noised_rgb.pack(side="left", padx=5, fill="both", expand=True)

        self.lbl_noise_img_noised_ycbcr = ttk.Label(
            frame_noise_preview, text="Noised YCbCr", anchor="center",
            borderwidth=2, relief="groove", width=30
        )
        self.lbl_noise_img_noised_ycbcr.pack(side="left", padx=5, fill="both", expand=True)

        # Hasil uji ketahanan noise
        frame_noise_result = ttk.Frame(frame_noise)
        frame_noise_result.pack(fill="x", padx=10, pady=3)

        # Info noise
        frame_noise_info = ttk.Frame(frame_noise_result)
        frame_noise_info.pack(fill="x", pady=2)
        ttk.Label(frame_noise_info, text="Info Noise (rata-rata):", width=22, anchor="w").pack(side="left")
        self.lbl_noise_info = ttk.Label(
            frame_noise_info, text="-", foreground="purple", font=("Arial", 9)
        )
        self.lbl_noise_info.pack(side="left", padx=5)

        # Hasil RGB dan YCbCr side-by-side
        frame_res_methods = ttk.Frame(frame_noise_result)
        frame_res_methods.pack(fill="both", expand=True, pady=5)

        # Kolom RGB
        frame_rgb_res = ttk.LabelFrame(frame_res_methods, text="Hasil Ekstraksi RGB")
        frame_rgb_res.pack(side="left", fill="both", expand=True, padx=(0, 5))

        self.lbl_noise_cer_rgb = ttk.Label(frame_rgb_res, text="CER: -", font=("Arial", 10, "bold"))
        self.lbl_noise_cer_rgb.pack(anchor="w", padx=10, pady=2)
        self.lbl_noise_err_rgb = ttk.Label(frame_rgb_res, text="Error: -", font=("Arial", 10))
        self.lbl_noise_err_rgb.pack(anchor="w", padx=10, pady=2)
        self.lbl_noise_status_rgb = ttk.Label(frame_rgb_res, text="Status: -", font=("Arial", 10))
        self.lbl_noise_status_rgb.pack(anchor="w", padx=10, pady=2)

        # Kolom YCbCr
        frame_ycbcr_res = ttk.LabelFrame(frame_res_methods, text="Hasil Ekstraksi YCbCr")
        frame_ycbcr_res.pack(side="right", fill="both", expand=True, padx=(5, 0))

        self.lbl_noise_cer_ycbcr = ttk.Label(frame_ycbcr_res, text="CER: -", font=("Arial", 10, "bold"))
        self.lbl_noise_cer_ycbcr.pack(anchor="w", padx=10, pady=2)
        self.lbl_noise_err_ycbcr = ttk.Label(frame_ycbcr_res, text="Error: -", font=("Arial", 10))
        self.lbl_noise_err_ycbcr.pack(anchor="w", padx=10, pady=2)
        self.lbl_noise_status_ycbcr = ttk.Label(frame_ycbcr_res, text="Status: -", font=("Arial", 10))
        self.lbl_noise_status_ycbcr.pack(anchor="w", padx=10, pady=2)

        # Inisialisasi path noise
        self.noise_cover_path = None
        self.noise_message_path = None

    def batch_load_covers(self):
        filepaths = filedialog.askopenfilenames(title="Pilih Gambar Cover", filetypes=[("PNG Images", "*.png")])
        if filepaths:
            self.batch_covers = list(filepaths)
            self.lbl_batch_covers.config(text=f"{len(self.batch_covers)} gambar terpilih", foreground="black")

    def batch_load_texts(self):
        filepaths = filedialog.askopenfilenames(title="Pilih File Teks", filetypes=[("Text Files", "*.txt")])
        if filepaths:
            self.batch_texts = list(filepaths)
            self.lbl_batch_texts.config(text=f"{len(self.batch_texts)} file teks terpilih", foreground="black")

    def hitung_cer(self, pesan_asli, pesan_ekstrak):
        if pesan_asli == pesan_ekstrak:
            return 0.0, 0
        min_len = min(len(pesan_asli), len(pesan_ekstrak))
        error_count = sum(1 for i in range(min_len) if pesan_asli[i] != pesan_ekstrak[i])
        error_count += abs(len(pesan_asli) - len(pesan_ekstrak))
        cer = (error_count / len(pesan_asli)) * 100 if len(pesan_asli) > 0 else 0.0
        return cer, error_count

    def batch_run_tests(self):
        if not self.batch_covers:
            return messagebox.showwarning("Peringatan", "Pilih minimal 1 gambar cover!")
        if not self.batch_texts:
            return messagebox.showwarning("Peringatan", "Pilih minimal 1 file teks!")

        # Clear existing table
        for item in self.tree_batch.get_children():
            self.tree_batch.delete(item)

        total_tasks = len(self.batch_covers) * len(self.batch_texts) * 2  # RGB & YCbCr
        self.progress_batch["maximum"] = total_tasks
        self.progress_batch["value"] = 0
        current_task = 0

        for cover_path in self.batch_covers:
            cover_name = os.path.basename(cover_path)
            for text_path in self.batch_texts:
                with open(text_path, 'r', encoding='utf-8') as f:
                    pesan_asli = f.read()
                
                pesan_len = len(pesan_asli)

                for mode in ["RGB", "YCbCr"]:
                    base = os.path.splitext(cover_name)[0]
                    stego_path = f"batch_stego_{base}_{mode}.png"
                    
                    try:
                        # 1. Penyisipan
                        start_sisip = time.perf_counter()
                        if mode == "RGB":
                            ksl.sisipkan_stego(cover_path, stego_path, pesan_asli)
                        else:
                            ksl.sisipkan_stego_ycbcr(cover_path, stego_path, pesan_asli)
                        waktu_sisip = time.perf_counter() - start_sisip

                        # 2. Hitung MSE & PSNR
                        mse, psnr = ksl.hitung_mse_psnr(cover_path, stego_path)
                        psnr_str = "∞" if psnr == float('inf') else f"{psnr:.2f}"
                        
                        # 3. Ekstraksi
                        start_ekstrak = time.perf_counter()
                        if mode == "RGB":
                            pesan_ekstrak = ksl.ekstrak_stego(stego_path)
                        else:
                            pesan_ekstrak = ksl.ekstrak_stego_ycbcr(stego_path)
                        waktu_ekstrak = time.perf_counter() - start_ekstrak

                        # 4. Hitung CER
                        cer_val, err_count = self.hitung_cer(pesan_asli, pesan_ekstrak)
                        status = "LULUS" if cer_val == 0.0 else "GAGAL"

                        self.tree_batch.insert("", "end", values=(
                            cover_name, f"{pesan_len} ch", mode, f"{cer_val:.2f}", err_count, 
                            f"{mse:.4f}", psnr_str, f"{waktu_sisip:.4f}", f"{waktu_ekstrak:.4f}", status
                        ))

                    except Exception as e:
                        self.tree_batch.insert("", "end", values=(
                            cover_name, f"{pesan_len} ch", mode, "ERROR", "-", "-", "-", "-", "-", "ERROR"
                        ))
                    
                    finally:
                        if os.path.exists(stego_path):
                            os.remove(stego_path)
                    
                    current_task += 1
                    self.progress_batch["value"] = current_task
                    self.update_idletasks()
        
        messagebox.showinfo("Selesai", "Pengujian batch selesai!")

    def batch_export_csv(self):
        items = self.tree_batch.get_children()
        if not items:
            return messagebox.showwarning("Peringatan", "Tidak ada hasil untuk diekspor!")
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            title="Simpan Hasil Pengujian Batch"
        )
        if not filepath:
            return
        
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                headers = [self.tree_batch.heading(c)["text"] for c in self.tree_batch["columns"]]
                writer.writerow(headers)
                
                for item in items:
                    writer.writerow(self.tree_batch.item(item)["values"])
            messagebox.showinfo("Sukses", f"Hasil berhasil diekspor ke:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Error", f"Gagal menyimpan CSV: {str(e)}")

    # ==================== HANDLER UJI KETAHANAN NOISE ====================
    def noise_load_cover(self):
        filepath = filedialog.askopenfilename(
            title="Pilih Gambar Asli (Cover PNG)",
            filetypes=[("PNG Images", "*.png")]
        )
        if filepath:
            self.noise_cover_path = filepath
            self.lbl_noise_img_path.config(text=filepath, foreground="black")
            self.tampilkan_gambar(filepath, self.lbl_noise_img_asli)
            self.lbl_noise_img_noised_rgb.config(image='', text="Noised RGB")
            self.lbl_noise_img_noised_ycbcr.config(image='', text="Noised YCbCr")

    def noise_load_message(self):
        filepath = filedialog.askopenfilename(
            title="Pilih File Plaintext Asli",
            filetypes=[("Text Files", "*.txt"), ("Semua File", "*.*")]
        )
        if filepath:
            self.noise_message_path = filepath
            self.lbl_noise_msg_path.config(text=filepath, foreground="black")

    def proses_noise_test(self):
        if not self.noise_cover_path:
            return messagebox.showwarning("Peringatan", "Pilih gambar asli (Cover PNG) terlebih dahulu!")
        if not self.noise_message_path:
            return messagebox.showwarning("Peringatan", "Pilih file plaintext (.txt) terlebih dahulu!")

        kunci = self.noise_entry_key.get()
        if not kunci:
            return messagebox.showwarning("Peringatan", "Masukkan passphrase untuk enkripsi!")

        # Parse probabilitas noise
        try:
            noise_pct = float(self.noise_entry_prob.get())
            noise_prob = noise_pct / 100.0  # Konversi persen ke probabilitas (0.001% → 0.00001)
        except ValueError:
            return messagebox.showerror("Error", "Nilai probabilitas noise tidak valid! Masukkan angka (contoh: 0.001)")

        # Reset labels
        self.lbl_noise_cer_rgb.config(text="CER: ⏳", foreground="black")
        self.lbl_noise_cer_ycbcr.config(text="CER: ⏳", foreground="black")
        self.lbl_noise_info.config(text="⏳ Memproses...")
        self.update_idletasks()

        base_path, ext = os.path.splitext(self.noise_cover_path)
        temp_stego_rgb = f"{base_path}_temp_stego_RGB{ext}"
        temp_stego_ycbcr = f"{base_path}_temp_stego_YCbCr{ext}"
        noised_rgb = f"{base_path}_noised_sp_RGB{ext}"
        noised_ycbcr = f"{base_path}_noised_sp_YCbCr{ext}"

        try:
            # 1. Baca plaintext asli
            with open(self.noise_message_path, 'r', encoding='utf-8') as f:
                plaintext = f.read().strip()

            # 2. Enkripsi plaintext dengan passphrase → ciphertext hex asli
            ciphertext_asli = ksl.aes_enkripsi(plaintext, kunci)

            # Convert ciphertext hex to raw bytes format for embedding
            try:
                raw_bytes = bytes.fromhex(ciphertext_asli)
                pesan_to_embed = raw_bytes.decode('latin-1')
            except ValueError:
                return messagebox.showerror("Error", "Gagal mengkonversi ciphertext hex ke raw bytes.")

            # 3. Lakukan steganografi pada gambar cover
            ksl.sisipkan_stego(self.noise_cover_path, temp_stego_rgb, pesan_to_embed)
            ksl.sisipkan_stego_ycbcr(self.noise_cover_path, temp_stego_ycbcr, pesan_to_embed)

            # 4. Tambahkan noise Salt & Pepper pada gambar stego sementara
            noise_info_rgb = ksl.tambah_noise_salt_pepper(temp_stego_rgb, noised_rgb, prob=noise_prob)
            noise_info_ycbcr = ksl.tambah_noise_salt_pepper(temp_stego_ycbcr, noised_ycbcr, prob=noise_prob)

            # 5. Ekstrak pesan dari gambar stego yang sudah diberi noise dan hitung CER
            def ekstrak_dan_hitung(noised_path, mode, ciphertext_asli):
                try:
                    if mode == "RGB":
                        pesan_ekstrak = ksl.ekstrak_stego(noised_path)
                    else:
                        pesan_ekstrak = ksl.ekstrak_stego_ycbcr(noised_path)
                    ciphertext_ekstrak = pesan_ekstrak.encode('latin-1').hex()
                    return self.hitung_cer(ciphertext_asli, ciphertext_ekstrak)
                except Exception:
                    return 100.0, len(ciphertext_asli)

            cer_rgb, err_rgb = ekstrak_dan_hitung(noised_rgb, "RGB", ciphertext_asli)
            cer_ycbcr, err_ycbcr = ekstrak_dan_hitung(noised_ycbcr, "YCbCr", ciphertext_asli)

            # Tampilkan gambar noised
            self.tampilkan_gambar(noised_rgb, self.lbl_noise_img_noised_rgb)
            self.tampilkan_gambar(noised_ycbcr, self.lbl_noise_img_noised_ycbcr)

            # Tampilkan hasil
            avg_noise_pct = (noise_info_rgb['noise_percentage'] + noise_info_ycbcr['noise_percentage']) / 2
            self.lbl_noise_info.config(
                text=f"~{avg_noise_pct:.4f}% piksel terkena noise"
            )

            def get_status_ui(cer_val, err_count):
                if cer_val == 0.0:
                    return "CER: 0.00%", "green", f"Error: 0 karakter", "Status: ✅ LULUS", "green"
                elif cer_val < 10:
                    return f"CER: {cer_val:.2f}%", "orange", f"Error: {err_count} karakter", "Status: ⚠️ GAGAL", "orange"
                else:
                    return f"CER: {cer_val:.2f}%", "red", f"Error: {err_count} karakter", "Status: ❌ GAGAL", "red"

            t_cer_rgb, c_cer_rgb, t_err_rgb, t_stat_rgb, c_stat_rgb = get_status_ui(cer_rgb, err_rgb)
            self.lbl_noise_cer_rgb.config(text=t_cer_rgb, foreground=c_cer_rgb)
            self.lbl_noise_err_rgb.config(text=t_err_rgb)
            self.lbl_noise_status_rgb.config(text=t_stat_rgb, foreground=c_stat_rgb)

            t_cer_ycbcr, c_cer_ycbcr, t_err_ycbcr, t_stat_ycbcr, c_stat_ycbcr = get_status_ui(cer_ycbcr, err_ycbcr)
            self.lbl_noise_cer_ycbcr.config(text=t_cer_ycbcr, foreground=c_cer_ycbcr)
            self.lbl_noise_err_ycbcr.config(text=t_err_ycbcr)
            self.lbl_noise_status_ycbcr.config(text=t_stat_ycbcr, foreground=c_stat_ycbcr)

            # Bersihkan file sementara
            for p in [temp_stego_rgb, temp_stego_ycbcr]:
                if os.path.exists(p): os.remove(p)

            messagebox.showinfo(
                "Hasil Uji Ketahanan Noise",
                f"Uji coba selesai untuk kedua mode!\n"
                f"Probabilitas Noise: {noise_pct}%\n\n"
                f"--- Hasil RGB ---\n"
                f"CER: {cer_rgb:.2f}% ({err_rgb} error)\n\n"
                f"--- Hasil YCbCr ---\n"
                f"CER: {cer_ycbcr:.2f}% ({err_ycbcr} error)"
            )

        except Exception as e:
            for p in [temp_stego_rgb, temp_stego_ycbcr]:
                if 'p' in locals() and os.path.exists(p): os.remove(p)

            self.lbl_noise_info.config(text="ERROR")
            self.lbl_noise_cer_rgb.config(text="CER: ERROR", foreground="red")
            self.lbl_noise_cer_ycbcr.config(text="CER: ERROR", foreground="red")
            messagebox.showerror("Error", f"Gagal menjalankan uji ketahanan noise: {str(e)}")


if __name__ == "__main__":
    app = SkripsiGUI()
    app.mainloop()