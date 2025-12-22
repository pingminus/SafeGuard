package encryption

import (
	"io"
	"os"
	"safeguard/utils"
)

func EncryptXOR(inputFile, key, outputFile string) {
	xorFile(inputFile, key, outputFile)
}

func DecryptXOR(inputFile, key, outputFile string) {
	xorFile(inputFile, key, outputFile)
}

func xorFile(inputFile, key, outputFile string) {
	in, err := os.Open(inputFile)
	if err != nil {
		utils.ErrorCout("Failed to open input file")
		return
	}
	defer in.Close()

	if outputFile == "" {
		outputFile = inputFile + ".xor"
	}

	out, err := os.Create(outputFile)
	if err != nil {
		utils.ErrorCout("Failed to create output file")
		return
	}
	defer out.Close()

	keyBytes := []byte(key)
	buffer := make([]byte, 4096)

	keyIndex := 0

	for {
		n, err := in.Read(buffer)
		if n > 0 {
			for i := 0; i < n; i++ {
				buffer[i] ^= keyBytes[keyIndex]
				keyIndex = (keyIndex + 1) % len(keyBytes)
			}
			out.Write(buffer[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			utils.ErrorCout("File read error")
			return
		}
	}

	utils.SuccessCout("XOR operation completed: " + outputFile)
}
