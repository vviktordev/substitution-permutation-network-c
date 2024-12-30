# Substitution-Permutation Network implementation in C
**WARNING!** This implementation is **NOT** cryptographically secure and should not be used outside educational purposes. See details below.

## How to run (on linux)

Clone the project and run `spn.bin` supplying appropriate arguments (mode input_file_path output_file_path encryption_key).

To encrypt file `input.txt` with password `password` and save the encrypted file as `output.enc`, run:

```bash
  ./spn.bin e input.txt output.enc password
```

Then to decrypt `output.enc` and save it as `decrypted.txt`, run:

```bash
  ./spn.bin d output.enc decrypted.txt password
```

`mode` can be either `e` for encryption or `d` for decryption. You can also compile the binary on your own with a compiler of your choice, like:

```bash
  clang main.c sha256.c -o binary.out
```

## About the implementation

The algorithm uses a **16-bit block size**. The key is the **SHA256 hash** of the supplied password generated using [Brad Conte's SHA256 C implementation](https://github.com/B-Con/crypto-algorithms/tree/master). The hash is then split into 16-bit chunks - one for each round ("round keys"). **4 rounds** of encryption are applied.

Decryption is achieved by running the algorithm "in reverse". The round keys generated are applied in reverse order, and the decryption Substitution-box is an inverse of the encryption S-box. The Permutation-box is self-inverse.

The implementation operates on **binaries of files**, not on text. That means you can feed it any type of file - image, pdf, etc. and it will work without any problems.

The Substitution-box used is the S1 0yyyy0 S-box of the DES algorithm - more details [here](https://en.wikipedia.org/wiki/DES_supplementary_material#Substitution_boxes_(S-boxes)).

## Why is it not secure?

This implementation has been created as a programming project during my first semester in college. Little care has been put into making it cryptographically secure. The list of problems includes, but is not limited to:
- Electronic Code Book (ECB) mode of operation
  - Unsuitable for encrypting data larger than 1-block wide because of vulnerabilities to known-plaintext attacks
  - Reveals patterns in encrypted data - check out [the ECB penguing](https://words.filippo.io/the-ecb-penguin/)
- Lack of proper key derivation algorithm
- Small block size (16 bits)
- Small number of rounds (4)
- Small key size (64 bits)
- Use of a static S-box and P-box
