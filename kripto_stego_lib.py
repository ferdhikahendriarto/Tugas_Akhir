import math
import time
import cv2
import struct
import bitstring
import numpy as np

# Import modul kriptografi
from BitVector import BitVector
import AESencryptfunc as enc
import AESdecryptfunc as dec

# Import modul steganografi
import zigzag as zz
import image_preparation as img

# 1. FUNGSI KRIPTOGRAFI AES
def aes_enkripsi(message, passphrase):

    if len(passphrase) < 16:
        passphrase = passphrase + "\0" * (16 - len(passphrase))
    elif len(passphrase) > 16:
        passphrase = passphrase[:16]

    message_bv = BitVector(textstring=message)

    if len(message_bv) % 128 != 0:
        message_bv.pad_from_right(128 - (len(message_bv) % 128))

    PassPhrase = BitVector(textstring=passphrase)

    roundkeys = [enc.findroundkey(PassPhrase.get_bitvector_in_hex(), 1)]
    for i in range(2, 11):
        roundkeys.append(enc.findroundkey(roundkeys[-1], i))

    outputhex = ""

    for i in range(0, len(message_bv), 128):
        block = message_bv[i:i+128]

        # AddRoundKey awal (Ronde 0)
        resultbv = block ^ PassPhrase
        
        if i == 0:
            print("\n" + "="*50)
            print("BUKTI PERHITUNGAN MATRIKS (BLOK 1)")
            print("="*50)
            print(f"Plaintext (Hex)       : {block.get_bitvector_in_hex()}")
            print(f"Passphrase (Hex)      : {PassPhrase.get_bitvector_in_hex()}")
            print(f"State Awal (Ronde 0)  : {resultbv.get_bitvector_in_hex()}")
            print("-" * 50)

        for r in range(9):
            hexstate = resultbv.get_bitvector_in_hex()
            hexstate = enc.subbyte(hexstate)
            hexstate = enc.shiftrow(hexstate)

            bv = BitVector(hexstring=hexstate)
            hexstate = enc.mixcolumn(bv)

            bv1 = BitVector(hexstring=hexstate)
            bv2 = BitVector(hexstring=roundkeys[r])

            resultbv = bv1 ^ bv2
            
            # Print hasil setiap ronde
            if i == 0:
                print(f"State Akhir Ronde {r+1}   : {resultbv.get_bitvector_in_hex()}")

        # Final Round (Ronde 10)
        hexstate = resultbv.get_bitvector_in_hex()
        hexstate = enc.subbyte(hexstate)
        hexstate = enc.shiftrow(hexstate)

        bv1 = BitVector(hexstring=hexstate)
        bv2 = BitVector(hexstring=roundkeys[9])

        resultbv = bv1 ^ bv2
        
        if i == 0:
            print("-" * 50)
            print(f"State Akhir Ronde 10  : {resultbv.get_bitvector_in_hex()}")
            print("="*50 + "\n")

        outputhex += resultbv.get_bitvector_in_hex()

    return outputhex


def aes_dekripsi(message_hex, passphrase):

    if len(passphrase) < 16:
        passphrase = passphrase + "\0" * (16 - len(passphrase))
    elif len(passphrase) > 16:
        passphrase = passphrase[:16]

    PassPhrase = BitVector(textstring=passphrase)

    roundkeys = [dec.findroundkey(PassPhrase.get_bitvector_in_hex(), 1)]
    for i in range(2, 11):
        roundkeys.append(dec.findroundkey(roundkeys[-1], i))

    asciioutput = ""

    for i in range(0, len(message_hex), 32):

        block = message_hex[i:i+32]

        bv1 = BitVector(hexstring=block)
        bv2 = BitVector(hexstring=roundkeys[9])

        resultbv = bv1 ^ bv2

        hexstate = resultbv.get_bitvector_in_hex()
        hexstate = dec.invshiftrow(hexstate)
        hexstate = dec.invsubbyte(hexstate)

        for r in range(8, -1, -1):

            bv1 = BitVector(hexstring=hexstate)
            bv2 = BitVector(hexstring=roundkeys[r])

            resultbv = bv1 ^ bv2
            hexstate = resultbv.get_bitvector_in_hex()

            bv3 = BitVector(hexstring=hexstate)
            hexstate = dec.invmixcolumn(bv3)

            hexstate = dec.invshiftrow(hexstate)
            hexstate = dec.invsubbyte(hexstate)

        bv1 = BitVector(hexstring=hexstate)

        resultbv = bv1 ^ PassPhrase

        asciioutput += resultbv.get_bitvector_in_ascii().replace('\x00', '')

    return asciioutput



# 2. FUNGSI STEGANOGRAFI DCT 
def embed_dct(encoded_bits, dct_blocks):

    encoded_bits.pos = 0
    encoded_data_len = bitstring.pack('uint:32', len(encoded_bits))
    data_stream = encoded_data_len + encoded_bits

    for block in dct_blocks:
        # Mulai dari i=2 (skip DC=0 dan AC pertama=1 yang paling tidak stabil)
        for i in range(2, len(block)):

            if data_stream.pos >= len(data_stream):
                return dct_blocks

            coeff = int(block[i])

            # Hanya koefisien positif > 1, konsisten dengan extract_dct
            if coeff > 1:
                bit = data_stream.read(1).uint
                coeff = (coeff & ~1) | bit
                block[i] = np.float32(coeff)

    raise ValueError("Data terlalu besar untuk gambar")


def extract_dct(dct_blocks):
    extracted_data = bitstring.BitStream()
    for block in dct_blocks:
        # WAJIB SAMA dengan embed_dct: mulai dari i=2, hanya positif > 1
        for i in range(2, len(block)):
            curr_coeff = int(block[i])
            if curr_coeff > 1:
                extracted_data.append(bitstring.pack('uint:1', curr_coeff & 1))
    return extracted_data


def _verify_and_correct_dct_coefficients(channel_uint8, expected_zigzag_blocks,
                                          quant_table, image_width, max_iterations=10):
    corrected = channel_uint8.copy()
    blocks_per_row = image_width // 8

    # Identifikasi blok-blok yang punya koefisien embeddable (optimisasi:
    # skip ~99% blok solid-color yang tidak punya koefisien > 1)
    active_blocks = []
    for bi, expected_zz in enumerate(expected_zigzag_blocks):
        for ci in range(2, len(expected_zz)):
            if int(expected_zz[ci]) > 1:
                active_blocks.append(bi)
                break

    total_corrected = 0
    for iteration in range(max_iterations):
        n_mismatches = 0

        for bi in active_blocks:
            row = (bi // blocks_per_row) * 8
            col = (bi % blocks_per_row) * 8

            # DCT + kuantisasi blok saat ini
            block_f32 = np.float32(corrected[row:row+8, col:col+8])
            dct_block = cv2.dct(block_f32)
            quant_block = np.around(np.divide(dct_block, quant_table))
            actual_zz = zz.zigzag(quant_block)
            expected_zz = expected_zigzag_blocks[bi]

            # Cek mismatch pada posisi embeddable (koefisien > 1, mulai index 2)
            diff_zz = np.zeros_like(expected_zz)
            has_mismatch = False

            for ci in range(2, len(expected_zz)):
                exp_val = int(expected_zz[ci])
                act_val = int(actual_zz[ci])
                # Cek posisi yang mempengaruhi sinkronisasi extract_dct:
                # baik koefisien yang seharusnya > 1 maupun yang tidak seharusnya > 1
                if (exp_val > 1 or act_val > 1) and exp_val != act_val:
                    diff_zz[ci] = expected_zz[ci] - actual_zz[ci]
                    has_mismatch = True
                    n_mismatches += 1

            if has_mismatch:
                # Hitung koreksi piksel via IDCT dari selisih koefisien
                diff_2d = zz.inverse_zigzag(diff_zz, vmax=8, hmax=8)
                diff_dequant = np.multiply(diff_2d, quant_table)
                pixel_correction = cv2.idct(diff_dequant)

                # Terapkan koreksi piksel
                adj = np.round(pixel_correction).astype(np.int16)
                block_u8 = corrected[row:row+8, col:col+8]
                new_block = np.clip(block_u8.astype(np.int16) + adj, 0, 255).astype(np.uint8)
                corrected[row:row+8, col:col+8] = new_block

        total_corrected += n_mismatches
        if n_mismatches == 0:
            break

    if total_corrected > 0:
        print(f"  [DCT Verify] {iteration + 1} iterasi, {total_corrected} koefisien dikoreksi")

    return corrected


def hitung_kapasitas_payload(cover_path, colorspace='RGB'):
    raw_cover_image = cv2.imread(cover_path, flags=cv2.IMREAD_COLOR)
    if raw_cover_image is None:
        raise ValueError("Gambar Cover tidak ditemukan.")

    raw_cover_image = cv2.cvtColor(raw_cover_image, cv2.COLOR_BGR2RGB)
    padded_image = img.pad_image_to_block(raw_cover_image)

    if colorspace == 'YCbCr':
        work_image = cv2.cvtColor(padded_image, cv2.COLOR_RGB2YCrCb)
        EMBED_CHANNEL = 0
    else:
        work_image = padded_image
        EMBED_CHANNEL = 1

    cover_image_f32 = np.float32(work_image)
    cover_obj = img.YCC_Image(cover_image_f32)

    QUANT_TABLE = img.JPEG_STD_LUM_QUANT_TABLE

    dct_blocks = [cv2.dct(block) for block in cover_obj.channels[EMBED_CHANNEL]]
    dct_quants = [np.around(np.divide(item, QUANT_TABLE)) for item in dct_blocks]
    sorted_coefficients = [zz.zigzag(block) for block in dct_quants]

    # Hitung jumlah koefisien yang bisa dipakai untuk embedding
    # (koefisien positif > 1, mulai dari index 2)
    capacity_bits = 0
    for block in sorted_coefficients:
        for i in range(2, len(block)):
            coeff = int(block[i])
            if coeff > 1:
                capacity_bits += 1

    # Kurangi 32 bit untuk header panjang data
    usable_bits = max(0, capacity_bits - 32)

    h, w = padded_image.shape[:2]
    total_blocks = len(sorted_coefficients)

    return {
        'capacity_bits': usable_bits,
        'capacity_bytes': usable_bits // 8,
        'capacity_chars': usable_bits // 8,
        'image_width': w,
        'image_height': h,
        'total_blocks': total_blocks,
    }


def sisipkan_stego(cover_path, stego_path, secret_message_string):
    raw_cover_image = cv2.imread(cover_path, flags=cv2.IMREAD_COLOR)
    if raw_cover_image is None:
        raise ValueError("Gambar Cover tidak ditemukan.")

    # Konversi BGR (default OpenCV) → RGB
    raw_cover_image = cv2.cvtColor(raw_cover_image, cv2.COLOR_BGR2RGB)

    padded_image = img.pad_image_to_block(raw_cover_image)

    # Embed langsung di ruang RGB (Green channel / index 1).
    # Green channel dipilih karena paling dekat dengan luminance secara perseptual.
    cover_image_f32 = np.float32(padded_image)
    cover_rgb = img.YCC_Image(cover_image_f32)
    stego_image = cover_image_f32.copy()

    # Proses dan embed hanya di Green channel (index 1 = G dalam RGB)
    EMBED_CHANNEL = 1
    QUANT_TABLE   = img.JPEG_STD_LUM_QUANT_TABLE

    dct_blocks        = [cv2.dct(block) for block in cover_rgb.channels[EMBED_CHANNEL]]
    dct_quants        = [np.around(np.divide(item, QUANT_TABLE)) for item in dct_blocks]
    sorted_coefficients = [zz.zigzag(block) for block in dct_quants]

    secret_data = bitstring.BitStream()
    for char in secret_message_string.encode('latin-1'):
        secret_data.append(bitstring.pack('uint:8', char))

    # Hitung kapasitas embedding (koefisien positif > 1, mulai dari index 2)
    capacity_bits = 0
    for block in sorted_coefficients:
        for i in range(2, len(block)):
            coeff = int(block[i])
            if coeff > 1:
                capacity_bits += 1
    usable_capacity_bits = max(0, capacity_bits - 32)  # minus header 32-bit

    message_bits = len(secret_data)

    embedded_dct_blocks   = embed_dct(secret_data, sorted_coefficients)
    desorted_coefficients = [zz.inverse_zigzag(block, vmax=8, hmax=8) for block in embedded_dct_blocks]
    dct_dequants          = [np.multiply(data, QUANT_TABLE) for data in desorted_coefficients]
    idct_blocks           = [cv2.idct(block) for block in dct_dequants]

    stego_image[:,:,EMBED_CHANNEL] = np.asarray(
        img.stitch_8x8_blocks_back_together(cover_rgb.width, idct_blocks))

    # np.round() sebelum uint8 mencegah float truncation yang bisa menggeser
    # nilai piksel ±1 dan menyebabkan boundary drift saat ekstraksi
    final_stego_image = np.uint8(np.round(np.clip(stego_image, 0, 255)))

    # Verifikasi & koreksi koefisien DCT yang bergeser akibat rounding float->uint8
    # (penting untuk gambar solid-color seperti bendera dimana koefisien kecil rentan bergeser)
    final_stego_image[:,:,EMBED_CHANNEL] = _verify_and_correct_dct_coefficients(
        final_stego_image[:,:,EMBED_CHANNEL],
        sorted_coefficients,
        QUANT_TABLE,
        cover_rgb.width
    )

    # Konversi RGB → BGR untuk cv2.imwrite (format penyimpanan OpenCV)
    final_stego_image = cv2.cvtColor(final_stego_image, cv2.COLOR_RGB2BGR)
    cv2.imwrite(stego_path, final_stego_image)

    # Return payload info
    utilization = (message_bits / usable_capacity_bits * 100) if usable_capacity_bits > 0 else 0
    return {
        'message_bits': message_bits,
        'message_bytes': message_bits // 8,
        'capacity_bits': usable_capacity_bits,
        'capacity_bytes': usable_capacity_bits // 8,
        'utilization_pct': utilization,
    }


def ekstrak_stego(stego_path):
    stego_image = cv2.imread(stego_path, flags=cv2.IMREAD_COLOR)
    if stego_image is None:
        raise ValueError("Gambar Stego tidak ditemukan.")

    # Konversi BGR → RGB, konsisten dengan sisipkan_stego
    stego_image = cv2.cvtColor(stego_image, cv2.COLOR_BGR2RGB)

    stego_image_f32 = np.float32(stego_image)
    stego_rgb = img.YCC_Image(stego_image_f32)

    EMBED_CHANNEL = 1
    QUANT_TABLE   = img.JPEG_STD_LUM_QUANT_TABLE

    dct_blocks          = [cv2.dct(block) for block in stego_rgb.channels[EMBED_CHANNEL]]
    dct_quants          = [np.around(np.divide(item, QUANT_TABLE)) for item in dct_blocks]
    sorted_coefficients = [zz.zigzag(block) for block in dct_quants]

    recovered_data = extract_dct(sorted_coefficients)
    recovered_data.pos = 0

    # Mengambil nilai panjang data
    try:
        data_len = int(recovered_data.read('uint:32') / 8)
    except bitstring.ReadError:
        raise ValueError("Gambar tidak memiliki data steganografi yang valid (bit kosong).")

    # SANITY CHECK: Cegah crash jika bit panjang data rusak
    if data_len <= 0 or data_len > 10000:
        raise ValueError(f"Panjang pesan tidak wajar ({data_len}). Gambar rusak, kapasitas kurang, atau bukan stego image.")

    extracted_data = bytes()
    for _ in range(data_len): 
        try:
            extracted_data += struct.pack('>B', recovered_data.read('uint:8'))
        except bitstring.ReadError:
            break

    return extracted_data.decode('latin-1', errors='replace')

# 2b. FUNGSI STEGANOGRAFI DCT (YCbCr)
def sisipkan_stego_ycbcr(cover_path, stego_path, secret_message_string):
    """Versi YCbCr: konversi RGB->YCrCb, embed di Y channel, lalu konversi balik."""
    raw_cover_image = cv2.imread(cover_path, flags=cv2.IMREAD_COLOR)
    if raw_cover_image is None:
        raise ValueError("Gambar Cover tidak ditemukan.")

    # Konversi BGR (default OpenCV) → RGB
    raw_cover_image = cv2.cvtColor(raw_cover_image, cv2.COLOR_BGR2RGB)

    padded_image = img.pad_image_to_block(raw_cover_image)

    # Konversi RGB -> YCrCb
    ycrcb_image = cv2.cvtColor(padded_image, cv2.COLOR_RGB2YCrCb)
    cover_image_f32 = np.float32(ycrcb_image)
    cover_ycc = img.YCC_Image(cover_image_f32)
    stego_image_f32 = cover_image_f32.copy()

    # Embed di Y channel (index 0 pada YCrCb)
    EMBED_CHANNEL = 0
    QUANT_TABLE   = img.JPEG_STD_LUM_QUANT_TABLE

    dct_blocks        = [cv2.dct(block) for block in cover_ycc.channels[EMBED_CHANNEL]]
    dct_quants        = [np.around(np.divide(item, QUANT_TABLE)) for item in dct_blocks]
    sorted_coefficients = [zz.zigzag(block) for block in dct_quants]

    secret_data = bitstring.BitStream()
    for char in secret_message_string.encode('latin-1'):
        secret_data.append(bitstring.pack('uint:8', char))

    # Hitung kapasitas embedding (koefisien positif > 1, mulai dari index 2)
    capacity_bits = 0
    for block in sorted_coefficients:
        for i in range(2, len(block)):
            coeff = int(block[i])
            if coeff > 1:
                capacity_bits += 1
    usable_capacity_bits = max(0, capacity_bits - 32)  # minus header 32-bit

    message_bits = len(secret_data)

    embedded_dct_blocks   = embed_dct(secret_data, sorted_coefficients)
    desorted_coefficients = [zz.inverse_zigzag(block, vmax=8, hmax=8) for block in embedded_dct_blocks]
    dct_dequants          = [np.multiply(data, QUANT_TABLE) for data in desorted_coefficients]
    idct_blocks           = [cv2.idct(block) for block in dct_dequants]

    stego_image_f32[:,:,EMBED_CHANNEL] = np.asarray(
        img.stitch_8x8_blocks_back_together(cover_ycc.width, idct_blocks))

    # Konversi kembali YCrCb -> RGB dengan KOREKSI round-trip
    # Masalah: YCrCb->RGB->YCrCb menyebabkan rounding error pada Y channel,
    # yang merusak bit yang sudah disisipkan.
    # Solusi: iterative pixel correction — adjust RGB agar Y tetap terjaga.
    stego_ycrcb = np.uint8(np.round(np.clip(stego_image_f32, 0, 255)))

    # Verifikasi & koreksi koefisien DCT pada Y channel sebelum konversi warna
    # (memastikan semua koefisien stabil sebelum Y dipertahankan melalui round-trip RGB)
    stego_ycrcb[:,:,EMBED_CHANNEL] = _verify_and_correct_dct_coefficients(
        stego_ycrcb[:,:,EMBED_CHANNEL],
        sorted_coefficients,
        QUANT_TABLE,
        cover_ycc.width
    )

    target_y = stego_ycrcb[:,:,0].copy()  # Y yang HARUS dipertahankan (DCT sudah dikoreksi)

    # Konversi awal ke RGB
    stego_rgb = cv2.cvtColor(stego_ycrcb, cv2.COLOR_YCrCb2RGB)

    # Correction loop: adjust RGB pixels agar Y survive round-trip
    for _iteration in range(30):
        # Cek Y setelah round-trip RGB -> YCrCb
        rt_ycrcb = cv2.cvtColor(stego_rgb, cv2.COLOR_RGB2YCrCb)
        diff = target_y.astype(np.int16) - rt_ycrcb[:,:,0].astype(np.int16)

        if not np.any(diff):
            break  # Semua Y sudah cocok!

        # Adjust channel RGB secara berurutan (G paling efektif, lalu R, lalu B)
        # Y = 0.299*R + 0.587*G + 0.114*B
        # Dalam RGB: index 0=R, 1=G, 2=B
        for channel, coeff in [(1, 0.587), (0, 0.299), (2, 0.114)]:
            rt_ycrcb = cv2.cvtColor(stego_rgb, cv2.COLOR_RGB2YCrCb)
            diff = target_y.astype(np.int16) - rt_ycrcb[:,:,0].astype(np.int16)

            if not np.any(diff):
                break

            mask = diff != 0
            adj = np.round(diff.astype(np.float64) / coeff).astype(np.int16)
            adj = np.clip(adj, -5, 5)  # Batasi adjustment agar tidak berlebihan

            stego_rgb_f = stego_rgb.astype(np.int16)
            stego_rgb_f[mask, channel] += adj[mask]
            stego_rgb = np.uint8(np.clip(stego_rgb_f, 0, 255))

    # Konversi RGB → BGR untuk cv2.imwrite (format penyimpanan OpenCV)
    stego_bgr_out = cv2.cvtColor(stego_rgb, cv2.COLOR_RGB2BGR)
    cv2.imwrite(stego_path, stego_bgr_out)

    # Return payload info
    utilization = (message_bits / usable_capacity_bits * 100) if usable_capacity_bits > 0 else 0
    return {
        'message_bits': message_bits,
        'message_bytes': message_bits // 8,
        'capacity_bits': usable_capacity_bits,
        'capacity_bytes': usable_capacity_bits // 8,
        'utilization_pct': utilization,
    }


def ekstrak_stego_ycbcr(stego_path):
    """Versi YCbCr: konversi RGB->YCrCb, ekstrak dari Y channel."""
    stego_image = cv2.imread(stego_path, flags=cv2.IMREAD_COLOR)
    if stego_image is None:
        raise ValueError("Gambar Stego tidak ditemukan.")

    # Konversi BGR → RGB → YCrCb
    stego_image = cv2.cvtColor(stego_image, cv2.COLOR_BGR2RGB)
    ycrcb_image = cv2.cvtColor(stego_image, cv2.COLOR_RGB2YCrCb)
    stego_image_f32 = np.float32(ycrcb_image)
    stego_ycc = img.YCC_Image(stego_image_f32)

    EMBED_CHANNEL = 0
    QUANT_TABLE   = img.JPEG_STD_LUM_QUANT_TABLE

    dct_blocks          = [cv2.dct(block) for block in stego_ycc.channels[EMBED_CHANNEL]]
    dct_quants          = [np.around(np.divide(item, QUANT_TABLE)) for item in dct_blocks]
    sorted_coefficients = [zz.zigzag(block) for block in dct_quants]

    recovered_data = extract_dct(sorted_coefficients)
    recovered_data.pos = 0

    try:
        data_len = int(recovered_data.read('uint:32') / 8)
    except bitstring.ReadError:
        raise ValueError("Gambar tidak memiliki data steganografi yang valid (bit kosong).")

    if data_len <= 0 or data_len > 10000:
        raise ValueError(f"Panjang pesan tidak wajar ({data_len}). Gambar rusak, kapasitas kurang, atau bukan stego image.")

    extracted_data = bytes()
    for _ in range(data_len):
        try:
            extracted_data += struct.pack('>B', recovered_data.read('uint:8'))
        except bitstring.ReadError:
            break

    return extracted_data.decode('latin-1', errors='replace')

# 3. FUNGSI PERBANDINGAN RGB vs YCbCr
def bandingkan_rgb_vs_ycbcr(cover_path, pesan):
    import os
    base_path, ext = os.path.splitext(cover_path)

    # --- Metode 1: RGB langsung ---
    stego_rgb_path = f"{base_path}_stego_RGB{ext}"
    sisipkan_stego(cover_path, stego_rgb_path, pesan)
    mse_rgb, psnr_rgb = hitung_mse_psnr(cover_path, stego_rgb_path)
    ch_rgb = hitung_mse_psnr_per_channel(cover_path, stego_rgb_path)

    # Cek apakah ekstraksi berhasil
    try:
        hasil_rgb = ekstrak_stego(stego_rgb_path)
        rgb_ok = (hasil_rgb.strip() == pesan.strip())
    except Exception:
        hasil_rgb = "[GAGAL]"
        rgb_ok = False

    # --- Metode 2: YCbCr ---
    stego_ycbcr_path = f"{base_path}_stego_YCbCr{ext}"
    sisipkan_stego_ycbcr(cover_path, stego_ycbcr_path, pesan)
    mse_ycbcr, psnr_ycbcr = hitung_mse_psnr(cover_path, stego_ycbcr_path)
    ch_ycbcr = hitung_mse_psnr_per_channel(cover_path, stego_ycbcr_path)

    # Cek apakah ekstraksi berhasil
    try:
        hasil_ycbcr = ekstrak_stego_ycbcr(stego_ycbcr_path)
        ycbcr_ok = (hasil_ycbcr.strip() == pesan.strip())
    except Exception:
        hasil_ycbcr = "[GAGAL]"
        ycbcr_ok = False

    return {
        'rgb': {
            'mse': mse_rgb,
            'psnr': psnr_rgb,
            'per_channel': ch_rgb,
            'stego_path': stego_rgb_path,
            'ekstrak_berhasil': rgb_ok,
            'pesan_hasil': hasil_rgb,
        },
        'ycbcr': {
            'mse': mse_ycbcr,
            'psnr': psnr_ycbcr,
            'per_channel': ch_ycbcr,
            'stego_path': stego_ycbcr_path,
            'ekstrak_berhasil': ycbcr_ok,
            'pesan_hasil': hasil_ycbcr,
        }
    }

def hitung_mse(image_asli_path, image_stego_path):
    img_asli  = cv2.imread(image_asli_path,  flags=cv2.IMREAD_COLOR)
    img_stego = cv2.imread(image_stego_path, flags=cv2.IMREAD_COLOR)
 
    if img_asli is None:
        raise ValueError(f"Gambar asli tidak ditemukan: {image_asli_path}")
    if img_stego is None:
        raise ValueError(f"Gambar stego tidak ditemukan: {image_stego_path}")
 
    # Pastikan kedua gambar memiliki ukuran yang sama
    # (stego mungkin di-pad, jadi crop ke ukuran asli)
    h_asli, w_asli = img_asli.shape[:2]
    img_stego_crop  = img_stego[:h_asli, :w_asli]
 
    # Konversi ke float64 untuk presisi perhitungan
    img_asli_f  = img_asli.astype(np.float64)
    img_stego_f = img_stego_crop.astype(np.float64)
 
    # Hitung MSE: rata-rata kuadrat selisih semua piksel semua channel
    mse_value = np.mean((img_asli_f - img_stego_f) ** 2)
 
    return mse_value
 
 
def hitung_psnr(image_asli_path, image_stego_path):
    mse_value = hitung_mse(image_asli_path, image_stego_path)
 
    if mse_value == 0:
        return math.inf  # Gambar identik sempurna
 
    MAX_I = 255.0
    psnr_value = 10 * math.log10((MAX_I ** 2) / mse_value)
 
    return psnr_value
 
 
def hitung_mse_psnr(image_asli_path, image_stego_path):
    img_asli  = cv2.imread(image_asli_path,  flags=cv2.IMREAD_COLOR)
    img_stego = cv2.imread(image_stego_path, flags=cv2.IMREAD_COLOR)
 
    if img_asli is None:
        raise ValueError(f"Gambar asli tidak ditemukan: {image_asli_path}")
    if img_stego is None:
        raise ValueError(f"Gambar stego tidak ditemukan: {image_stego_path}")
 
    h_asli, w_asli = img_asli.shape[:2]
    img_stego_crop  = img_stego[:h_asli, :w_asli]
 
    img_asli_f  = img_asli.astype(np.float64)
    img_stego_f = img_stego_crop.astype(np.float64)
 
    mse_value = np.mean((img_asli_f - img_stego_f) ** 2)
 
    if mse_value == 0:
        psnr_value = math.inf
    else:
        MAX_I = 255.0
        psnr_value = 10 * math.log10((MAX_I ** 2) / mse_value)
 
    return mse_value, psnr_value

def hitung_mse_psnr_per_channel(image_asli_path, image_stego_path):
    img_asli  = cv2.imread(image_asli_path,  flags=cv2.IMREAD_COLOR)
    img_stego = cv2.imread(image_stego_path, flags=cv2.IMREAD_COLOR)
 
    if img_asli is None:
        raise ValueError(f"Gambar asli tidak ditemukan: {image_asli_path}")
    if img_stego is None:
        raise ValueError(f"Gambar stego tidak ditemukan: {image_stego_path}")
 
    h_asli, w_asli = img_asli.shape[:2]
    img_stego_crop  = img_stego[:h_asli, :w_asli]
 
    # Konversi BGR → RGB agar label channel konsisten (R, G, B)
    img_asli       = cv2.cvtColor(img_asli, cv2.COLOR_BGR2RGB)
    img_stego_crop = cv2.cvtColor(img_stego_crop, cv2.COLOR_BGR2RGB)
 
    img_asli_f  = img_asli.astype(np.float64)
    img_stego_f = img_stego_crop.astype(np.float64)
 
    MAX_I = 255.0
    channel_names = ['R', 'G', 'B']
    results = {}
 
    for idx, name in enumerate(channel_names):
        mse_ch = np.mean((img_asli_f[:,:,idx] - img_stego_f[:,:,idx]) ** 2)
        if mse_ch == 0:
            psnr_ch = math.inf
        else:
            psnr_ch = 10 * math.log10((MAX_I ** 2) / mse_ch)
        results[name] = {'mse': mse_ch, 'psnr': psnr_ch}
 
    mse_overall = np.mean((img_asli_f - img_stego_f) ** 2)
    if mse_overall == 0:
        psnr_overall = math.inf
    else:
        psnr_overall = 10 * math.log10((MAX_I ** 2) / mse_overall)
 
    results['Overall'] = {'mse': mse_overall, 'psnr': psnr_overall}
 
    return results

# 4. FUNGSI NOISE SALT & PEPPER
def tambah_noise_salt_pepper(image_path, output_path, prob=0.00001):
    image = cv2.imread(image_path, flags=cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError(f"Gambar tidak ditemukan: {image_path}")

    noisy = image.copy()
    h, w, c = noisy.shape
    total_pixels = h * w

    # Generate random matrix untuk menentukan posisi noise
    rng = np.random.default_rng()
    random_matrix = rng.random((h, w))

    # Salt (putih): random < prob/2
    salt_mask = random_matrix < (prob / 2)
    noisy[salt_mask] = 255  # Semua channel jadi 255

    # Pepper (hitam): random > 1 - prob/2
    pepper_mask = random_matrix > (1 - prob / 2)
    noisy[pepper_mask] = 0  # Semua channel jadi 0

    salt_count = int(np.sum(salt_mask))
    pepper_count = int(np.sum(pepper_mask))
    affected = salt_count + pepper_count
    noise_pct = (affected / total_pixels) * 100 if total_pixels > 0 else 0.0

    cv2.imwrite(output_path, noisy)

    return {
        'total_pixels': total_pixels,
        'salt_pixels': salt_count,
        'pepper_pixels': pepper_count,
        'affected_pixels': affected,
        'noise_percentage': noise_pct,
    }