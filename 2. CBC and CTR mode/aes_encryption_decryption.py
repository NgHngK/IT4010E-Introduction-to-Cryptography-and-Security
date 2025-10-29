from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import binascii


def xor_bytes(a, b):
    result = []
    for i in range(len(a)):
        result.append(a[i] ^ b[i])
    return bytes(result)


def add_padding(data):
    padding_length = 16 - (len(data) % 16)
    padding = bytes([padding_length] * padding_length)
    return data + padding


def remove_padding(data):
    padding_length = data[-1]
    return data[:-padding_length]


def encrypt_cbc(key_hex, plaintext):
    key = binascii.unhexlify(key_hex)
    plaintext_bytes = plaintext.encode('utf-8')
    
    iv = get_random_bytes(16)
    padded_plaintext = add_padding(plaintext_bytes)
    
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = b''
    previous_block = iv
    
    for i in range(0, len(padded_plaintext), 16):
        plaintext_block = padded_plaintext[i:i+16]
        
        xored = xor_bytes(plaintext_block, previous_block)
        encrypted_block = cipher.encrypt(xored)
        ciphertext = ciphertext + encrypted_block
        
        previous_block = encrypted_block
    
    final_ciphertext = iv + ciphertext
    return binascii.hexlify(final_ciphertext).decode('utf-8')


def decrypt_cbc(key_hex, ciphertext_hex):
    key = binascii.unhexlify(key_hex)
    ciphertext = binascii.unhexlify(ciphertext_hex)
    
    iv = ciphertext[:16]
    encrypted_data = ciphertext[16:]
    
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = b''
    previous_block = iv
    
    for i in range(0, len(encrypted_data), 16):
        current_block = encrypted_data[i:i+16]
        
        decrypted = cipher.decrypt(current_block)
        plaintext_block = xor_bytes(decrypted, previous_block)
        plaintext = plaintext + plaintext_block
        
        previous_block = current_block
    
    plaintext = remove_padding(plaintext)
    return plaintext.decode('utf-8')


def encrypt_ctr(key_hex, plaintext):
    key = binascii.unhexlify(key_hex)
    plaintext_bytes = plaintext.encode('utf-8')
    
    nonce = get_random_bytes(16)
    
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = b''
    counter = int.from_bytes(nonce, byteorder='big')
    
    for i in range(0, len(plaintext_bytes), 16):
        plaintext_block = plaintext_bytes[i:i+16]
        
        counter_bytes = counter.to_bytes(16, byteorder='big')
        keystream = cipher.encrypt(counter_bytes)
        
        ciphertext_block = xor_bytes(plaintext_block, keystream[:len(plaintext_block)])
        ciphertext = ciphertext + ciphertext_block
        
        counter = counter + 1
    
    final_ciphertext = nonce + ciphertext
    return binascii.hexlify(final_ciphertext).decode('utf-8')


def decrypt_ctr(key_hex, ciphertext_hex):
    key = binascii.unhexlify(key_hex)
    ciphertext = binascii.unhexlify(ciphertext_hex)
    
    nonce = ciphertext[:16]
    encrypted_data = ciphertext[16:]
    
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = b''
    counter = int.from_bytes(nonce, byteorder='big')
    
    for i in range(0, len(encrypted_data), 16):
        current_block = encrypted_data[i:i+16]
        
        counter_bytes = counter.to_bytes(16, byteorder='big')
        keystream = cipher.encrypt(counter_bytes)
        
        plaintext_block = xor_bytes(current_block, keystream[:len(current_block)])
        plaintext = plaintext + plaintext_block
        
        counter = counter + 1
    
    return plaintext.decode('utf-8')


def main():
    print("--- DECRYPTION TESTS ---\n")
    
    print("Question 1 - CBC Mode:")
    cbc_key = "140b41b22a29beb4061bda66b6747e14"
    cbc_ct1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    plaintext1 = decrypt_cbc(cbc_key, cbc_ct1)
    print("Plaintext:", plaintext1)
    
    print("\nQuestion 2 - CBC Mode:")
    cbc_ct2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
    plaintext2 = decrypt_cbc(cbc_key, cbc_ct2)
    print("Plaintext:", plaintext2)
    
    print("\nQuestion 3 - CTR Mode:")
    ctr_key = "36f18357be4dbd77f050515c73fcf9f2"
    ctr_ct1 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
    plaintext3 = decrypt_ctr(ctr_key, ctr_ct1)
    print("Plaintext:", plaintext3)
    
    print("\nQuestion 4 - CTR Mode:")
    ctr_ct2 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
    plaintext4 = decrypt_ctr(ctr_key, ctr_ct2)
    print("Plaintext:", plaintext4)
    
    print("\n--- ENCRYPTION TESTS ---\n")
    
    print("Testing CBC Encryption:")
    test_plaintext = "Hello World!"
    test_key = "140b41b22a29beb4061bda66b6747e14"
    encrypted = encrypt_cbc(test_key, test_plaintext)
    print("Original:", test_plaintext)
    print("Encrypted (hex):", encrypted)
    decrypted = decrypt_cbc(test_key, encrypted)
    print("Decrypted:", decrypted)
    print("Match:", test_plaintext == decrypted)
    
    print("\nTesting CTR Encryption:")
    encrypted_ctr = encrypt_ctr(test_key, test_plaintext)
    print("Original:", test_plaintext)
    print("Encrypted (hex):", encrypted_ctr)
    decrypted_ctr = decrypt_ctr(test_key, encrypted_ctr)
    print("Decrypted:", decrypted_ctr)
    print("Match:", test_plaintext == decrypted_ctr)


if __name__ == "__main__":
    main()