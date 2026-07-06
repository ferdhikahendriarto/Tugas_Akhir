import cv2
import numpy as np
import os
import glob

def tambah_salt_pepper_noise(citra, persentase_noise):
    """
    Fungsi untuk menambahkan Salt & Pepper noise ke dalam citra digital.
    """
    citra_bernoise = np.copy(citra)
    probabilitas = persentase_noise / 100.0
    
    matriks_acak = np.random.rand(*citra.shape[:2])
    
    # 1. Salt (Titik Putih)
    citra_bernoise[matriks_acak < (probabilitas / 2)] = 255
    
    # 2. Pepper (Titik Hitam)
    kondisi_pepper = (matriks_acak >= (probabilitas / 2)) & (matriks_acak < probabilitas)
    citra_bernoise[kondisi_pepper] = 0
    
    return citra_bernoise

def proses_banyak_gambar(folder_input, folder_output, densitas_noise):
    """
    Fungsi untuk membaca semua gambar di folder input, 
    menambahkan noise, dan menyimpan ke folder output.
    """
    # Buat folder output jika belum ada
    if not os.path.exists(folder_output):
        os.makedirs(folder_output)
        print(f"Folder '{folder_output}' berhasil dibuat.")

    # Mencari semua file gambar (jpg, jpeg, png) di folder input
    ekstensi_gambar = ('*.jpg', '*.jpeg', '*.png')
    daftar_gambar = []
    for ekstensi in ekstensi_gambar:
        daftar_gambar.extend(glob.glob(os.path.join(folder_input, ekstensi)))

    if not daftar_gambar:
        print(f"Tidak ada gambar yang ditemukan di dalam folder '{folder_input}'.")
        return

    print(f"Ditemukan {len(daftar_gambar)} gambar. Memulai proses...")

    # Looping untuk memproses setiap gambar
    for path_gambar in daftar_gambar:
        # Mengambil nama file saja (contoh: 'foto1.jpg')
        nama_file = os.path.basename(path_gambar)
        
        # Membaca citra
        citra_asli = cv2.imread(path_gambar)
        
        if citra_asli is None:
            print(f"Gagal membaca gambar: {nama_file}")
            continue

        # Menambahkan noise
        citra_hasil = tambah_salt_pepper_noise(citra_asli, densitas_noise)

        # Menyimpan citra hasil ke folder output
        path_simpan = os.path.join(folder_output, f"noise_{nama_file}")
        cv2.imwrite(path_simpan, citra_hasil)
        
        print(f"Berhasil memproses dan menyimpan: {path_simpan}")

    print("Semua gambar telah selesai diproses!")

# ==========================================
# EKSEKUSI KODE
# ==========================================
if __name__ == "__main__":
    # 1. Tentukan nama folder tempat gambar-gambar asli berada
    FOLDER_INPUT = "D:\Dhika\KULIAH\TA\GAMBAR"
    
    # 2. Tentukan nama folder tempat hasil gambar akan disimpan
    FOLDER_OUTPUT = "D:\Dhika\KULIAH\TA\GAMBAR OUTPUT"
    
    # 3. Atur persentase noise ke 0.001%
    DENSITAS_NOISE = 0.001
    
    # Peringatan untuk pengguna
    if not os.path.exists(FOLDER_INPUT):
        print(f"Harap buat folder bernama '{FOLDER_INPUT}' dan masukkan gambar-gambar Anda ke dalamnya terlebih dahulu.")
    else:
        # Jalankan proses batch
        proses_banyak_gambar(FOLDER_INPUT, FOLDER_OUTPUT, DENSITAS_NOISE)