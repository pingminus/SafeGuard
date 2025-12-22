package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"

	"safeguard/utils"
)

// File format:
// [8-byte magic] [16-byte salt] [16-byte iv] [ciphertext ...] [32-byte HMAC]
var magicHeader = []byte("ENCRv1.0")

func deriveKeys(salt []byte, password string) (encKey, macKey []byte) {
	h := sha256.Sum256(append(salt, []byte(password)...))
	enc := sha256.Sum256(append(h[:], 0x01))
	mac := sha256.Sum256(append(h[:], 0x02))
	return enc[:], mac[:]
}

func AES256EncryptFile(inputFile, outputFile, password string) bool {
	in, err := os.Open(inputFile)
	if err != nil {
		utils.ErrorCout("Failed to open input file")
		return false
	}
	defer in.Close()

	tmpOutPath := outputFile + ".tmp"
	out, err := os.Create(tmpOutPath)
	if err != nil {
		utils.ErrorCout("Failed to create output file")
		return false
	}
	defer func() {
		out.Close()
	}()

	// generate salt and iv
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		utils.ErrorCout("Failed to generate salt")
		return false
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		utils.ErrorCout("Failed to generate IV")
		return false
	}

	encKey, macKey := deriveKeys(salt, password)

	block, err := aes.NewCipher(encKey)
	if err != nil {
		utils.ErrorCout("Failed to create cipher")
		return false
	}

	stream := cipher.NewCTR(block, iv)

	// write header
	if _, err := out.Write(magicHeader); err != nil {
		utils.ErrorCout("Failed to write header")
		return false
	}
	if _, err := out.Write(salt); err != nil {
		utils.ErrorCout("Failed to write header")
		return false
	}
	if _, err := out.Write(iv); err != nil {
		utils.ErrorCout("Failed to write header")
		return false
	}

	mac := hmac.New(sha256.New, macKey)

	buf := make([]byte, 32*1024)
	encBuf := make([]byte, len(buf))
	for {
		n, rerr := in.Read(buf)
		if n > 0 {
			stream.XORKeyStream(encBuf[:n], buf[:n])
			if _, err := out.Write(encBuf[:n]); err != nil {
				utils.ErrorCout("Failed to write ciphertext")
				return false
			}
			if _, err := mac.Write(encBuf[:n]); err != nil {
				utils.ErrorCout("Failed to compute HMAC")
				return false
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			utils.ErrorCout("Failed to read input file")
			return false
		}
	}

	macSum := mac.Sum(nil)
	if _, err := out.Write(macSum); err != nil {
		utils.ErrorCout("Failed to write HMAC")
		out.Close()
		os.Remove(tmpOutPath)
		return false
	}

	if err := out.Close(); err != nil {
		os.Remove(tmpOutPath)
		utils.ErrorCout("Failed to finalize output file")
		return false
	}
	if err := os.Rename(tmpOutPath, outputFile); err != nil {
		os.Remove(tmpOutPath)
		utils.ErrorCout("Failed to finalize output file")
		return false
	}

	utils.SuccessCout("AES streaming encryption completed: " + filepath.Base(outputFile))
	return true
}

func AES256DecryptFile(inputFile, outputFile, password string) bool {
	in, err := os.Open(inputFile)
	if err != nil {
		utils.ErrorCout("Failed to open input file")
		return false
	}
	defer in.Close()

	fi, err := in.Stat()
	if err != nil {
		utils.ErrorCout("Failed to stat input file")
		return false
	}

	header := make([]byte, len(magicHeader))
	if _, err := io.ReadFull(in, header); err != nil {
		utils.ErrorCout("Failed to read header")
		return false
	}
	if string(header) != string(magicHeader) {
		utils.ErrorCout("Unsupported file format")
		return false
	}

	salt := make([]byte, 16)
	if _, err := io.ReadFull(in, salt); err != nil {
		utils.ErrorCout("Failed to read salt")
		return false
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(in, iv); err != nil {
		utils.ErrorCout("Failed to read IV")
		return false
	}

	encKey, macKey := deriveKeys(salt, password)
	block, err := aes.NewCipher(encKey)
	if err != nil {
		utils.ErrorCout("Failed to create cipher")
		return false
	}
	stream := cipher.NewCTR(block, iv)

	// compute sizes: remaining bytes = ciphertext + mac
	total := fi.Size()
	headerLen := int64(len(magicHeader) + 16 + aes.BlockSize)
	macLen := int64(sha256.Size)
	if total < headerLen+macLen {
		utils.ErrorCout("File too short or corrupted")
		return false
	}
	ciphertextLen := total - headerLen - macLen

	// create temp output file to avoid writing plaintext before MAC verification
	tmpOutPath := outputFile + ".tmp"
	out, err := os.Create(tmpOutPath)
	if err != nil {
		utils.ErrorCout("Failed to create temp output file")
		return false
	}

	mac := hmac.New(sha256.New, macKey)

	buf := make([]byte, 32*1024)
	encBuf := make([]byte, len(buf))
	var readSoFar int64
	for readSoFar < ciphertextLen {
		toRead := int64(len(buf))
		if remaining := ciphertextLen - readSoFar; remaining < toRead {
			toRead = remaining
		}
		n, rerr := in.Read(buf[:toRead])
		if n > 0 {
			// buf[:n] holds ciphertext
			if _, err := mac.Write(buf[:n]); err != nil {
				out.Close()
				os.Remove(tmpOutPath)
				utils.ErrorCout("Failed to compute HMAC")
				return false
			}
			stream.XORKeyStream(encBuf[:n], buf[:n])
			if _, err := out.Write(encBuf[:n]); err != nil {
				out.Close()
				os.Remove(tmpOutPath)
				utils.ErrorCout("Failed to write plaintext")
				return false
			}
			readSoFar += int64(n)
		}
		if rerr != nil && rerr != io.EOF {
			out.Close()
			os.Remove(tmpOutPath)
			utils.ErrorCout("Failed to read ciphertext")
			return false
		}
	}

	// read stored mac
	storedMac := make([]byte, macLen)
	if _, err := io.ReadFull(in, storedMac); err != nil {
		out.Close()
		os.Remove(tmpOutPath)
		utils.ErrorCout("Failed to read HMAC")
		return false
	}

	computedMac := mac.Sum(nil)
	if !hmac.Equal(storedMac, computedMac) {
		out.Close()
		os.Remove(tmpOutPath)
		utils.ErrorCout("HMAC verification failed: file corrupted or wrong password")
		return false
	}

	out.Close()
	if err := os.Rename(tmpOutPath, outputFile); err != nil {
		os.Remove(tmpOutPath)
		utils.ErrorCout("Failed to finalize output file")
		return false
	}

	utils.SuccessCout("AES streaming decryption completed: " + filepath.Base(outputFile))
	return true
}
