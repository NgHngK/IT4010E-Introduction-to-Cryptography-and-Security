# Explanation of the AES Encryption Code

This file explains a Python program that uses AES to encrypt and decrypt messages. It describes how the code works, what is needed to run it, and what the final decoded messages are.

# Library Used

This code uses a special set of tools from a library called pycryptodome. This library helps the code perform the encryption and decryption steps. Before running the code, this library must be installed on the computer.

# How to Run the Code

First, the computer needs to have Python 3 installed. The pycryptodome library must also be installed. This can be done by opening a terminal (command prompt) and typing pip install pycryptodome.

After that, the code should be saved in a file with a .py name, such as decrypt.py. To run the code, open a terminal, go to the folder where the file is saved, and type python decrypt.py. The code will then start. It will run the main part of the program, which will show the decoded messages.

# How the Decryption Works

The code can decode messages that were encrypted in two different ways: CBC mode and CTR mode. Both methods use AES, which is a common and strong wa  y to encrypt things. Before looking at the main methods, it is helpful to know about the small "helper" functions.

The xor_bytes function combines two blocks of data. It uses a special math operation called XOR. This operation is very useful in encryption because it is reversible. For example, if Block A is combined with Block B to get Result C, then combining Result C with Block B will get Block A back.

The add_padding and remove_padding functions are used for CBC mode. AES encryption works on 16-byte blocks. If a message's last part is not a full 16 bytes, add_padding adds extra bytes to fill it. After decoding, remove_padding looks at the last byte to see how many extra bytes were added and safely removes them to get the original message.

CBC Mode Decryption (The decrypt_cbc function)

CBC means "Cipher Block Chaining." This name is used because each block of text is "chained" to the one before it. To decode a block of encrypted text, the code needs the secret key and also the encrypted block that came just before it.

The formula for this process can be written as:

Plaintext_Block = Decrypt(Current_Encrypted_Block) XOR Previous_Encrypted_Block

Here is the process: The function first reads the full encrypted message. The very first 16 bytes are a starter block called the Initialization Vector (IV). The rest of the message is the encrypted data. The code takes the first encrypted block, decodes it with the secret key, and then mixes (XORs) it with the IV. This gives the first plaintext block. Then, it takes the second encrypted block, decodes it, and mixes it with the first encrypted block. This process continues like a chain until all blocks are decoded. Finally, the remove_padding function cleans up the end of the message.

CTR Mode Decryption (The decrypt_ctr function)

CTR means "Counter." This method is very different and does not need padding. It works by creating a secret "keystream" that is used to mix with the encrypted text. The encrypted message itself is never decoded.

The formula for this process can be written as:

Plaintext_Block = Encrypted_Block XOR Encrypt(Counter)

In simple words, this formula says: The Plaintext Block is found by mixing (XOR) the Encrypted Block... with a Keystream. This keystream is made by Encrypting a Counter with the key.

Here is the process: The function first reads the message. The first 16 bytes are a "Nonce," which is just a random starting number for the counter. The rest is the encrypted data. The code then takes that starting number and encrypts it (not decodes it) using the secret key. This creates the first keystream block. This keystream is mixed with the first encrypted block to get the first plaintext block. Then, the code adds 1 to the counter's number, encrypts this new number, and gets a new keystream. This is mixed with the second encrypted block. This repeats until all the data is decoded.

# All Recovered Plaintexts

When the program runs, it decodes and prints four messages. Here are the original messages that were recovered:

Question 1 - CBC Mode:
Plaintext: Basic CBC mode encryption needs padding.

Question 2 - CBC Mode:
Plaintext: Our implementation uses rand. IV

Question 3 - CTR Mode:
Plaintext: CTR mode lets you build a stream cipher from a block cipher.

Question 4 - CTR Mode:
Plaintext: Always avoid the two time pad!
