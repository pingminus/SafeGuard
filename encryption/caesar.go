package encryption

import (
	"io"
	"os"
	"safeguard/utils"
)

func EncryptCaesar(inputFile string, shift int, outputFile string) {
	caesarFile(inputFile, shift, outputFile)
}

func DecryptCaesar(inputFile string, shift int, outputFile string) {
	caesarFile(inputFile, -shift, outputFile)
}

func caesarFile(inputFile string, shift int, outputFile string) {
	in, err := os.Open(inputFile)
	if err != nil {
		utils.ErrorCout("Failed to open input file")
		return
	}
	defer in.Close()

	if outputFile == "" {
		outputFile = inputFile + ".caesar"
	}

	out, err := os.Create(outputFile)
	if err != nil {
		utils.ErrorCout("Failed to create output file")
		return
	}
	defer out.Close()

	buffer := make([]byte, 4096)
	for {
		n, err := in.Read(buffer)
		if n > 0 {
			for i := 0; i < n; i++ {
				buffer[i] = byte(int(buffer[i]+byte(shift)) % 256)
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

	utils.SuccessCout("Caesar operation completed: " + outputFile)
}
