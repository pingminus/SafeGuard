<div align="center">
  <img src="static/safeguardLogo.png" alt="Safeguard Logo" width="500">
</div>

```bash
./safeguard --Version
1.0
```

<br>
<div align="center">
  <img src="static/image.png" alt="Safeguard-Terminal" width="600">
</div>
<br>
<br>
Safeguard is a fast, lightweight, cross-platform command-line file encryption tool written in Go.

---

## ⚠️ Security Notice

Safeguard uses **AES-256**, it provides confidentiality and integrity for encrypted files. Short notice:

- This tool is for convenience/testing — not for protecting high‑value secrets.
- `--inplace` overwrites originals; back up important files first.

---

## Installation

### Build req. Go

```bash
git clone https://github.com/pingplus/safeguard.git
cd safeguard
go build -o encrypter
```

## Usage

General syntax:

```bash
./safeguard <file> <action> <cipher> [options]
```

Actions:

- `--encrypt` or `e` Encrypt a file
- `--decrypt` or `d` Decrypt a file
- `--decrypt-directory` or `de` Decrypt a whole directory (decrypting directory not available yet)

Options:

- `--inplace` decrypt/encrypt a file in place (experimental)
- `--key` add key
- `--output` specify the output name

Supported ciphers:

```bash
./safeguard --list-ciphers
[i] Available ciphers:
  xor
  caesar
  aes-256
```

---

## AES-256

Encrypt a file:

```bash
encrypter secret.txt e aes-256 --key "your-strong-password"
# or
encrypter secret.txt --encrypt aes-256 --key "your-strong-password" --output secret.txt.aes
```

Decrypt a file:

```bash
./safeguard secret.txt d aes-256 --key "your-strong-password"
# or
./safeguard secret.txt --decrypt aes-256 --key "your-strong-password" --output secret.txt.dec
```

---

## More Examples

- Encrypt with AES-256 and write in place:

```bash
./safeguard secrets.txt e aes-256 --key "123123123123123123123123" --inplace
# -> creates secrets.txt but encrypted
```

- Decrypt with AES-256 and specify output file :

```bash
./safeguard secrets.txt.aes d aes-256 --key "123123123123123123123123" --output secrets_decrypted.txt
```
