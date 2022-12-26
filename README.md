# ChaCha

Simple implementation of file encryption with ChaCha20-Poly1305

## About ChaCha20-Poly1305

- ChaCha20
    - symmetric stream cipher
    - 256 bits/32 bytes key
    - 96 bits/12 bytes nonce as initial value (IV)
    - nonce could be public, key should be private
    - each encryption should apply different key and nonce combination
- Poly1305
    - authenticator for Authenticated Encryption with Associated Data (AEAD)
    - 128 bits/16 bytes message authentication code (MAC)
- Encrypt
    - ChaCha20 [ message ] + Poly1305 [ MAC ]
    - ChaCha20 encrypt the plaintext message and generate the ciphertext message, both size are the same
    - Poly1305 generate the message authentication code and append to the ciphertext message, so the ciphertext message size will be bigger
- Decrypt
    - Poly1305 verify integrity of the ciphertext message by check message auth code
    - ChaCha20 decrypt the ciphertext message with the same key and nonce
- Built in JDK since Java 11
- Spec: [RFC7539](https://tools.ietf.org/html/rfc7539)

## Implementation

- PBKDF2-HMAC-SHA256 key-derivation
- Append nonce and salt of key generation on ciphertext message for decryption

## Usage

Build jar by maven and launch with below argument

```sh
# encrypt source file
java -jar /path/to/jar [e] [password] [source file path] [destination file path]
# encrypt source file with verbose output
java -jar /path/to/jar [ev] [password] [source file path] [destination file path]
# decrypt source file
java -jar /path/to/jar [d] [password] [source file path] [destination file path]
# decrypt source file with verbose output
java -jar /path/to/jar [dv] [password] [source file path] [destination file path]
```
