import tkinter as tk
from tkinter import filedialog, messagebox

# 初始置换表
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# 逆初始置换表
IP_INV = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# 扩展置换表
E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

# 置换选择表1
PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

# 置换选择表2
PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

# 置换表
P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]

# S盒
S_BOX = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],  # S1
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],  # S2
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],  # S3
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],  # S4
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],  # S5
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],  # S6
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],  # S7
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]  # S8
]
flag = [1]

# 将密钥从64位压缩到56位
def permute(block, table):
    return [block[x - 1] for x in table]


# 左移操作
def shift_left(block, n):
    return block[n:] + block[:n]


# 生成16轮的子密钥
def generate_subkey(key):
    key = permute(key, PC1)  # 置换选择1
    C0, D0 = key[:28], key[28:]
    subkeys = []
    for shift in [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]:
        C0 = shift_left(C0, shift)
        D0 = shift_left(D0, shift)
        subkeys.append(permute(C0 + D0, PC2))  # 置换选择2
    print("第十五轮轮密钥",subkeys[-2])
    print("第十六轮轮密钥",subkeys[-1])
    return subkeys


# S盒代替
def substitute(block):
    output = []
    for i in range(8):
        row = (block[i * 6] << 1) + block[i * 6 + 5]
        col = (block[i * 6 + 1] << 3) + (block[i * 6 + 2] << 2) + (block[i * 6 + 3] << 1) + block[i * 6 + 4]
        output.extend(int_to_bin(S_BOX[i][row][col], 4))
    return output


# 二进制转整数
def bin_to_int(bits):
    return int(''.join(str(bit) for bit in bits), 2)


# 整数转二进制
def int_to_bin(value, bits):
    return [int(bit) for bit in f'{value:0{bits}b}']


# F函数
def f(R, K):
    R = permute(R, E)  # 扩展置换
    R = [r ^ k for r, k in zip(R, K)]
    R = substitute(R)  # S盒代替
    return permute(R, P)  # P置换


# DES加密/解密核心函数
def des_core(block, subkeys, encrypt=True):
    block = permute(block, IP)  # 初始置换
    L, R = block[:32], block[32:]
    subkeys = subkeys if encrypt else subkeys[::-1]
    i = 0
    for subkey in subkeys:
        i = i + 1
        L, R = R, [l ^ f for l, f in zip(L, f(R, subkey))]
        block = permute(R + L, IP_INV)  # 逆初始置换
        if encrypt == True and (flag[0] == 1 or flag[0] == 2):
            if i >= 15:  # 输出最后两轮加密后的中间值
                if i == 15:
                    print("最后两轮加密后值:")
                print(f"Round {i} L: {L}, R: {R}")
                flag[0] = flag[0] + 1
        elif encrypt == False:
            if i >= 15:  # 输出最后两轮加密后的中间值
                if i == 15:
                    print("最后两轮解密后值:")
                print(f"Round {i} L: {L}, R: {R}")
    return block


# 加密
def encrypt(block, subkeys):
    return des_core(block, subkeys, encrypt=True)


# 解密
def decrypt(block, subkeys):
    return des_core(block, subkeys, encrypt=False)


# 将消息块转为二进制
def block_to_bin(block):
    return sum([int_to_bin(byte, 8) for byte in block], [])


# 将二进制转换为消息块
def bin_to_block(bits):
    return bytes(bin_to_int(bits[i:i + 8]) for i in range(0, len(bits), 8))


# 填充消息到64位的倍数
def pad_message(message):
    padding_len = 8 - (len(message) % 8)
    return message + bytes([padding_len] * padding_len)


# 删除填充
def unpad_message(message):
    padding_len = message[-1]
    return message[:-padding_len]


# ECB模式加密
def ecb_encrypt(message, key):
    subkeys = generate_subkey(block_to_bin(key))
    padded_message = pad_message(message)
    ciphertext = b''
    for i in range(0, len(padded_message), 8):
        block = block_to_bin(padded_message[i:i + 8])
        encrypted_block = encrypt(block, subkeys)
        ciphertext += bin_to_block(encrypted_block)
    return ciphertext


# ECB模式解密
def ecb_decrypt(ciphertext, key):
    subkeys = generate_subkey(block_to_bin(key))
    decrypted_message = b''
    for i in range(0, len(ciphertext), 8):
        block = block_to_bin(ciphertext[i:i + 8])
        decrypted_block = decrypt(block, subkeys)
        decrypted_message += bin_to_block(decrypted_block)
    return unpad_message(decrypted_message)


# CBC模式加密
def cbc_encrypt(message, key, iv):
    subkeys = generate_subkey(block_to_bin(key))
    padded_message = pad_message(message)
    ciphertext = b''
    prev_block = block_to_bin(iv)
    for i in range(0, len(padded_message), 8):
        block = block_to_bin(padded_message[i:i + 8])
        block = [b ^ p for b, p in zip(block, prev_block)]
        encrypted_block = encrypt(block, subkeys)
        ciphertext += bin_to_block(encrypted_block)
        prev_block = encrypted_block
    return ciphertext


# CBC模式解密
def cbc_decrypt(ciphertext, key, iv):
    subkeys = generate_subkey(block_to_bin(key))
    decrypted_message = b''
    prev_block = block_to_bin(iv)
    for i in range(0, len(ciphertext), 8):
        block = block_to_bin(ciphertext[i:i + 8])
        decrypted_block = decrypt(block, subkeys)
        decrypted_block = [d ^ p for d, p in zip(decrypted_block, prev_block)]
        decrypted_message += bin_to_block(decrypted_block)
        prev_block = block
    return unpad_message(decrypted_message)


# CFB模式加密
def cfb_encrypt(message, key, iv):
    subkeys = generate_subkey(block_to_bin(key))
    padded_message = pad_message(message)
    ciphertext = b''
    prev_block = block_to_bin(iv)
    for i in range(0, len(padded_message), 8):
        encrypted_block = encrypt(prev_block, subkeys)
        block = block_to_bin(padded_message[i:i + 8])
        cipher_block = [b ^ e for b, e in zip(block, encrypted_block)]
        ciphertext += bin_to_block(cipher_block)
        prev_block = cipher_block
    return ciphertext


# CFB模式解密
def cfb_decrypt(ciphertext, key, iv):
    subkeys = generate_subkey(block_to_bin(key))
    decrypted_message = b''
    prev_block = block_to_bin(iv)
    for i in range(0, len(ciphertext), 8):
        encrypted_block = encrypt(prev_block, subkeys)
        block = block_to_bin(ciphertext[i:i + 8])
        plain_block = [b ^ e for b, e in zip(block, encrypted_block)]
        decrypted_message += bin_to_block(plain_block)
        prev_block = block
    return unpad_message(decrypted_message)


# OFB模式加密
def ofb_encrypt(message, key, iv):
    subkeys = generate_subkey(block_to_bin(key))
    padded_message = pad_message(message)
    ciphertext = b''
    prev_block = block_to_bin(iv)
    for i in range(0, len(padded_message), 8):
        encrypted_block = encrypt(prev_block, subkeys)
        block = block_to_bin(padded_message[i:i + 8])
        cipher_block = [b ^ e for b, e in zip(block, encrypted_block)]
        ciphertext += bin_to_block(cipher_block)
        prev_block = encrypted_block
    return ciphertext


# OFB模式解密
def ofb_decrypt(ciphertext, key, iv):
    return ofb_encrypt(ciphertext, key, iv)  # OFB模式加密和解密是相同的


# 图像化界面
def read_file(file_path):
    with open(file_path, 'rb') as file:
        return file.read()


def write_file(file_path, data):
    with open(file_path, 'wb') as file:
        file.write(data)


def perform_encryption_decryption(mode, operation, file_path, output_path, key, iv_nonce=None):
    key = key.encode('utf-8')
    if iv_nonce:
        iv_nonce = iv_nonce.encode('utf-8')
        data = read_file(file_path)
    if operation == 'encrypt':
        if mode == 'ECB':
            data = read_file(file_path)
            result = ecb_encrypt(data, key)
        elif mode == 'CBC':
            result = cbc_encrypt(data, key, iv_nonce)
        elif mode == 'CFB':
            result = cfb_encrypt(data, key, iv_nonce)
        elif mode == 'OFB':
            result = ofb_encrypt(data, key, iv_nonce)
    elif operation == 'decrypt':
        if mode == 'ECB':
            data = read_file(file_path)
            result = ecb_decrypt(data, key)
        elif mode == 'CBC':
            result = cbc_decrypt(data, key, iv_nonce)
        elif mode == 'CFB':
            result = cfb_decrypt(data, key, iv_nonce)
        elif mode == 'OFB':
            result = ofb_decrypt(data, key, iv_nonce)

    write_file(output_path, result)


def select_file(entry):
    file_path = filedialog.askopenfilename()
    entry.delete(0, tk.END)
    entry.insert(0, file_path)


def select_output_file(entry):
    file_path = filedialog.asksaveasfilename()
    entry.delete(0, tk.END)
    entry.insert(0, file_path)


def start_operation():
    mode = mode_var.get()
    operation = operation_var.get()
    file_path = input_file_entry.get()
    output_path = output_file_entry.get()
    key = key_entry.get()
    iv_nonce = iv_nonce_entry.get() if mode != 'ECB' else None

    if not (file_path and output_path and key):
        messagebox.showerror("错误", "请填写所有必需的字段")
        return
    try:
        perform_encryption_decryption(mode, operation, file_path, output_path, key, iv_nonce)
        messagebox.showinfo("完成", f"{operation.capitalize()}ion 完成!")
    except Exception as e:
        messagebox.showerror("错误", str(e))


# 创建主窗口
root = tk.Tk()
root.title("DES 加密/解密工具")

tk.Label(root, text="选择模式:").grid(row=0, column=0, padx=10, pady=5)
mode_var = tk.StringVar(value="ECB")
modes = ["ECB", "CBC", "CFB", "OFB"]
tk.OptionMenu(root, mode_var, *modes).grid(row=0, column=1, padx=10, pady=5)

tk.Label(root, text="选择操作:").grid(row=1, column=0, padx=10, pady=5)
operation_var = tk.StringVar(value="encrypt")
operations = [("加密", "encrypt"), ("解密", "decrypt")]
for text, value in operations:
    tk.Radiobutton(root, text=text, variable=operation_var, value=value).grid(row=1, column=1, sticky='w')

tk.Label(root, text="输入文件:").grid(row=2, column=0, padx=10, pady=5)
input_file_entry = tk.Entry(root, width=50)
input_file_entry.grid(row=2, column=1, padx=10, pady=5)
tk.Button(root, text="选择文件", command=lambda: select_file(input_file_entry)).grid(row=2, column=2, padx=10, pady=5)

tk.Label(root, text="输出文件:").grid(row=3, column=0, padx=10, pady=5)
output_file_entry = tk.Entry(root, width=50)
output_file_entry.grid(row=3, column=1, padx=10, pady=5)
tk.Button(root, text="选择文件", command=lambda: select_output_file(output_file_entry)).grid(row=3, column=2, padx=10,
                                                                                         pady=5)

tk.Label(root, text="密钥:").grid(row=4, column=0, padx=10, pady=5)
key_entry = tk.Entry(root, width=50)
key_entry.grid(row=4, column=1, padx=10, pady=5)

tk.Label(root, text="IV/Nonce:").grid(row=5, column=0, padx=10, pady=5)
iv_nonce_entry = tk.Entry(root, width=50)
iv_nonce_entry.grid(row=5, column=1, padx=10, pady=5)

tk.Button(root, text="开始", command=start_operation).grid(row=6, column=0, columnspan=3, pady=20)

root.mainloop()