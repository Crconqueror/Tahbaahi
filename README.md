# Tahbaahi
Cipher Tool for Secure Communication
# Tahbaahi – Cipher Tool for Secure Communication

Tahbaahi is an educational desktop application that demonstrates classical cryptographic techniques through a simple graphical interface. Pick a cipher, choose Encrypt or Decrypt, enter a message (and a key if needed), and see the result instantly.

> **Learning tool only.** Classical ciphers are easy to break with modern techniques. Do not use Tahbaahi to protect real or sensitive data.

Built for the *Computer & Network Security* mini project, Department of Computer Engineering, Vidyalankar Institute of Technology (AY 2025-26).

## Features

- Six classical ciphers: Atbash, Caesar, Rail Fence, Vernam, Vigenère, Playfair
- Encrypt and Decrypt modes
- Tkinter GUI with a four-step flow (cipher, mode, message, key)
- Input validation with plain-language error messages
- A note for each cipher explaining how it treats spaces, capital letters and symbols
- Copy-to-clipboard button for results
- No third-party dependencies (Python standard library only)

## Requirements

- Python 3.8 or later (tested on 3.12)
- Tkinter (included with the Windows and macOS installers; on Debian/Ubuntu run `sudo apt install python3-tk`)

## Run

```bash
python Tahbaahi 2.0.py or python Tahbaahi.py
```

## Supported ciphers

| Cipher | Key | Notes |
|---|---|---|
| Atbash | None | Case and spaces kept; self-inverse |
| Caesar | Whole number (shift) | Case and spaces kept |
| Rail Fence | Rails (2 or more) | Spaces are scrambled too; decryption needs the exact ciphertext |
| Vernam | Letters A–Z, same length as message | Letters only; output uppercase, no spaces |
| Vigenère | Keyword (letters) | Case and spaces kept; spaces don't use key letters |
| Playfair | Keyword (letters) | Letters only; J merged into I; filler X added, so decrypted text may contain extra X's |

## Project structure

The cipher functions (`atbash`, `caesar`, `railfence`, `vernam`, `vigenere`, `playfair`) share the signature `cipher(text, key, encrypt) -> str` and raise `CipherError` on invalid input. They contain no GUI code, so they can be imported and tested without opening a window. The `CIPHERS` dictionary drives the menu, key label and notice, so adding a cipher needs one function and one registry entry.

```python
from cipher_tool import caesar, vigenere

caesar("HELLO", "3", True)        # 'KHOOR'
vigenere("HELLO WORLD", "KEY", True)  # 'RIJVS UYVJN'
```

## Team

Aryan Gandhi · Abaan Mhaisker · Shams Tabrez Ahmed · Ayush Singasane

Supervisor: Prof. Shivani Herlekar

## License

Add a license of your choice (e.g. MIT) before publishing.
