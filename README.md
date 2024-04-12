# X9.31_CSPRNG
My implementation of the ANSI X9.31 Cryptographically Secure Pseudo Random Number Generator (CSPRNG).
I use the AES (Advanced Encryption Standard) algorithm to encrypt the vectors.
I also encrypt an image using AES in CTR mode to show its advantage over DES in Electronic Code Book (ECB) mode.

# key.txt
The key that is used in the AES algorithm.

# image.ppm
The image that needs to be encrypted.

# enc_image.ppm
The encrypted image using AES in CTR mode. Unlike ECB mode DES, the shape of the image is not preserved in the encrypted image.

# AES.py
The Python code that implements AES in CTR mode, showcasing its security. It also has a function x931 that generates random numbers using the ANSI X9.31 CSPRNG algorithm as documented in https://csrc.nist.rip/cryptval/rng/931rngext.pdf.
