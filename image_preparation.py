'''
Author: Mason Edgar (Modified for better PSNR)
ECE 529 - Algorithm Project
Image Steganography
'''
#------ External Libraries ------#
import cv2
import numpy as np
#================================#

# Numpy Macros
HORIZ_AXIS = 1
VERT_AXIS  = 0

# OPTION 1: JPEG Standard (Paling Agresif - PSNR ~25-35 dB)
# Ini yang Anda pakai sekarang - kompresi tinggi, PSNR rendah
JPEG_STD_LUM_QUANT_TABLE = np.asarray([
                                        [16, 11, 10, 16,  24, 40,   51,  61],
                                        [12, 12, 14, 19,  26, 58,   60,  55],
                                        [14, 13, 16, 24,  40, 57,   69,  56],
                                        [14, 17, 22, 29,  51, 87,   80,  62],
                                        [18, 22, 37, 56,  68, 109, 103,  77],
                                        [24, 36, 55, 64,  81, 104, 113,  92],
                                        [49, 64, 78, 87, 103, 121, 120, 101],
                                        [72, 92, 95, 98, 112, 100, 103,  99]
                                      ],
                                      dtype = np.float32)

JPEG_STD_CHR_QUANT_TABLE = np.asarray([
                                        [17, 18, 24, 47, 99, 99, 99, 99],
                                        [18, 21, 26, 66, 99, 99, 99, 99],
                                        [24, 26, 56, 99, 99, 99, 99, 99],
                                        [47, 66, 99, 99, 99, 99, 99, 99],
                                        [99, 99, 99, 99, 99, 99, 99, 99],
                                        [99, 99, 99, 99, 99, 99, 99, 99],
                                        [99, 99, 99, 99, 99, 99, 99, 99],
                                        [99, 99, 99, 99, 99, 99, 99, 99],
                                      ],
                                      dtype = np.float32)

# OPTION 2: Quality 90 (Moderate - PSNR ~35-42 dB) ✓ RECOMMENDED
# Kompresi sedang, keseimbangan baik antara kapasitas dan kualitas
JPEG_Q90_LUM_QUANT_TABLE = np.asarray([
                                        [ 3,  2,  2,  3,  5,  8, 10, 12],
                                        [ 2,  2,  3,  4,  5, 12, 12, 11],
                                        [ 3,  3,  3,  5,  8, 11, 14, 11],
                                        [ 3,  3,  4,  6, 10, 17, 16, 12],
                                        [ 4,  4,  7, 11, 14, 22, 21, 15],
                                        [ 5,  7, 11, 13, 16, 21, 23, 18],
                                        [10, 13, 16, 17, 21, 24, 24, 20],
                                        [14, 18, 19, 20, 22, 20, 21, 20]
                                      ],
                                      dtype = np.float32)

JPEG_Q90_CHR_QUANT_TABLE = np.asarray([
                                        [ 3,  4,  5,  9, 20, 20, 20, 20],
                                        [ 4,  4,  5, 13, 20, 20, 20, 20],
                                        [ 5,  5, 11, 20, 20, 20, 20, 20],
                                        [ 9, 13, 20, 20, 20, 20, 20, 20],
                                        [20, 20, 20, 20, 20, 20, 20, 20],
                                        [20, 20, 20, 20, 20, 20, 20, 20],
                                        [20, 20, 20, 20, 20, 20, 20, 20],
                                        [20, 20, 20, 20, 20, 20, 20, 20],
                                      ],
                                      dtype = np.float32)

# OPTION 3: Quality 95 (Sangat Halus - PSNR ~42-50 dB)
# Kompresi minimal, kualitas terbaik, tapi kapasitas embedding sedikit berkurang
JPEG_Q95_LUM_QUANT_TABLE = np.asarray([
                                        [ 2,  1,  1,  2,  2,  4,  5,  6],
                                        [ 1,  1,  1,  2,  3,  6,  6,  6],
                                        [ 1,  1,  2,  2,  4,  6,  7,  6],
                                        [ 1,  2,  2,  3,  5,  9,  8,  6],
                                        [ 2,  2,  4,  6,  7, 11, 10,  8],
                                        [ 2,  4,  6,  6,  8, 10, 11,  9],
                                        [ 5,  6,  8,  9, 10, 12, 12, 10],
                                        [ 7,  9, 10, 10, 11, 10, 10, 10]
                                      ],
                                      dtype = np.float32)

JPEG_Q95_CHR_QUANT_TABLE = np.asarray([
                                        [ 2,  2,  2,  5, 10, 10, 10, 10],
                                        [ 2,  2,  3,  7, 10, 10, 10, 10],
                                        [ 2,  3,  6, 10, 10, 10, 10, 10],
                                        [ 5,  7, 10, 10, 10, 10, 10, 10],
                                        [10, 10, 10, 10, 10, 10, 10, 10],
                                        [10, 10, 10, 10, 10, 10, 10, 10],
                                        [10, 10, 10, 10, 10, 10, 10, 10],
                                        [10, 10, 10, 10, 10, 10, 10, 10],
                                      ],
                                      dtype = np.float32)

# OPTION 4: LOSSLESS (Tidak ada quantization - PSNR sangat tinggi, tapi file besar)
# Hanya untuk testing - tidak praktis untuk steganografi real
LOSSLESS_QUANT_TABLE = np.ones((8, 8), dtype=np.float32)

# ==========================================
# PILIH TABEL YANG AKAN DIGUNAKAN DI SINI:
# ==========================================
# Ganti nilai di bawah ini untuk memilih kualitas:
# - JPEG_STD_xxx_QUANT_TABLE   → Standard (PSNR ~25-35 dB)
# - JPEG_Q90_xxx_QUANT_TABLE   → Quality 90 (PSNR ~35-42 dB) ✓ RECOMMENDED
# - JPEG_Q95_xxx_QUANT_TABLE   → Quality 95 (PSNR ~42-50 dB)
# - LOSSLESS_QUANT_TABLE       → Lossless (PSNR sangat tinggi, testing only)

# DEFAULT: Gunakan Q90 untuk keseimbangan optimal
ACTIVE_LUM_QUANT_TABLE = JPEG_Q90_LUM_QUANT_TABLE
ACTIVE_CHR_QUANT_TABLE = JPEG_Q90_CHR_QUANT_TABLE

# Atau bisa di-override via kode dengan memanggil set_quality()
def set_quality_level(quality='Q90'):
    """
    Fungsi untuk mengganti tabel kuantisasi secara dinamis
    
    Parameters:
        quality: 'STD' (standard), 'Q90' (recommended), 'Q95' (high quality), 'LOSSLESS'
    """
    global ACTIVE_LUM_QUANT_TABLE, ACTIVE_CHR_QUANT_TABLE
    
    if quality == 'STD':
        ACTIVE_LUM_QUANT_TABLE = JPEG_STD_LUM_QUANT_TABLE
        ACTIVE_CHR_QUANT_TABLE = JPEG_STD_CHR_QUANT_TABLE
    elif quality == 'Q90':
        ACTIVE_LUM_QUANT_TABLE = JPEG_Q90_LUM_QUANT_TABLE
        ACTIVE_CHR_QUANT_TABLE = JPEG_Q90_CHR_QUANT_TABLE
    elif quality == 'Q95':
        ACTIVE_LUM_QUANT_TABLE = JPEG_Q95_LUM_QUANT_TABLE
        ACTIVE_CHR_QUANT_TABLE = JPEG_Q95_CHR_QUANT_TABLE
    elif quality == 'LOSSLESS':
        ACTIVE_LUM_QUANT_TABLE = LOSSLESS_QUANT_TABLE
        ACTIVE_CHR_QUANT_TABLE = LOSSLESS_QUANT_TABLE
    else:
        raise ValueError(f"Unknown quality: {quality}. Use 'STD', 'Q90', 'Q95', or 'LOSSLESS'")
    
    print(f"✓ Tabel kuantisasi diset ke: {quality}")

# ==========================================

# Image container class
class YCC_Image(object):
    def __init__(self, cover_image):
        self.height, self.width = cover_image.shape[:2]
        self.channels = [
                         split_image_into_8x8_blocks(cover_image[:,:,0]),
                         split_image_into_8x8_blocks(cover_image[:,:,1]),
                         split_image_into_8x8_blocks(cover_image[:,:,2]),
                        ]


def stitch_8x8_blocks_back_together(Nc, block_segments):
    '''
    Take the array of 8x8 pixel blocks and put them together by row so the numpy.block() method can sitch it back together
    :param Nc: Number of pixels in the image (length-wise)
    :param block_segments:
    :return:
    '''
    image_rows = []
    temp = []
    for i in range(len(block_segments)):
        if i > 0 and not(i % int(Nc / 8)):
            image_rows.append(temp)
            temp = [block_segments[i]]
        else:
            temp.append(block_segments[i])
    image_rows.append(temp)

    return np.block(image_rows)

def pad_image_to_block(image):
    '''
    Pad image dimensions to be multiples of 8 using zero-padding.
    [PERBAIKAN] Fungsi ini WAJIB digunakan sebagai pengganti cv2.resize()
    agar tidak terjadi interpolasi piksel yang menambah distorsi.
    '''
    h, w = image.shape[:2]

    pad_h = (8 - h % 8) % 8
    pad_w = (8 - w % 8) % 8

    return np.pad(image,
        ((0, pad_h), (0, pad_w), (0,0)),
        mode='constant')

def split_image_into_8x8_blocks(image):

    blocks = []

    h, w = image.shape

    for y in range(0, h, 8):
        for x in range(0, w, 8):

            blocks.append(image[y:y+8, x:x+8])

    return blocks

