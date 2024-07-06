# DES
不同运行模式下的DES的加解密
这段代码实现了一个图形化用户界面的DES加密/解密工具。它包括加密和解密功能，并支持多种加密模式：ECB、CBC、CFB和OFB。以下是代码的各个部分及其功能的详细解释：

1. 常量定义部分：
    定义了DES算法中的置换表、扩展置换表、置换选择表、S盒等常量。这些表是DES算法中关键的部分，用于各种置换和替换操作。

2. 工具函数：
    permute(block, table)：根据给定的置换表对输入块进行置换。
    shift_left(block, n)：对块进行左移操作。
    generate_subkey(key)：生成16轮的子密钥。
    substitute(block)：根据S盒进行替换操作。
    bin_to_int(bits) 和 int_to_bin(value, bits)：二进制和整数之间的转换。
    f(R, K)：DES算法的F函数。
    des_core(block, subkeys, encrypt=True)：DES加密/解密的核心函数。

3. 加密/解密函数：
    encrypt(block, subkeys) 和 decrypt(block, subkeys)：分别实现加密和解密功能。
    block_to_bin(block) 和 bin_to_block(bits)：消息块和二进制之间的转换。
    pad_message(message) 和 unpad_message(message)：填充和去除填充。
    ecb_encrypt(message, key) 和 ecb_decrypt(ciphertext, key)：实现ECB模式的加密和解密。
    cbc_encrypt(message, key, iv) 和 cbc_decrypt(ciphertext, key, iv)：实现CBC模式的加密和解密。
    cfb_encrypt(message, key, iv) 和 cfb_decrypt(ciphertext, key, iv)：实现CFB模式的加密和解密。
    ofb_encrypt(message, key, iv) 和 ofb_decrypt(ciphertext, key, iv)：实现OFB模式的加密和解密。
4. 文件读写函数：
    read_file(file_path)：读取文件内容。
    write_file(file_path, data)：将数据写入文件。
5. 加密/解密操作函数：
    perform_encryption_decryption(mode, operation, file_path, output_path, key, iv_nonce)：根据用户选择的模式和操作执行加密或解密。

6. 图形化用户界面（GUI）：
    使用Tkinter库创建一个GUI窗口，提供选择文件、选择输出文件、输入密钥和IV/Nonce等功能。
    select_file(entry) 和 select_output_file(entry)：文件选择对话框。
    start_operation()：启动加密/解密操作，并根据用户输入进行相应的处理。
