package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"safeguard/encryption"
	"safeguard/utils"
	"strconv"
	"strings"
)


func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func isDirectory(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func confirmOverwrite(filename string) bool {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return true
	}

	fmt.Printf("File '%s' already exists. Overwrite? (y/n): ", filename)
	reader := bufio.NewReader(os.Stdin)
	resp, _ := reader.ReadString('\n')
	resp = strings.TrimSpace(resp)

	return resp == "y" || resp == "Y"
}

func listCiphers() {
	utils.InfoCout("Available ciphers:")
	fmt.Println("  xor")
	fmt.Println("  caesar")
	fmt.Println("  aes-256")
}
func encryptDirectory(directory string, encrypt bool, cipher string, key string, outputFile string) {
	utils.InfoCout("Processing directory " + directory)

	var successCount, failCount int

	filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			utils.ErrorCout("Walk error: " + err.Error())
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		utils.InfoCout("Processing file: " + path)

		switch cipher {
		case "xor":
			out := path + ".xor"
			if !encrypt {
				out = path + ".xor.dec"
			}
			if encrypt {
				encryption.EncryptXOR(path, key, out)
			} else {
				encryption.DecryptXOR(path, key, out)
			}
			successCount++

		case "caesar":
			shift, err := utils.ParseInt(key)
			if err != nil {
				utils.ErrorCout("Invalid caesar key for file: " + path)
				failCount++
				return nil
			}
			out := path + ".caesar"
			if !encrypt {
				out = path + ".caesar.dec"
			}
			if encrypt {
				encryption.EncryptCaesar(path, shift, out)
			} else {
				encryption.DecryptCaesar(path, shift, out)
			}
			successCount++

		case "aes-256":
			if len(key) < 16 {
				utils.ErrorCout("AES key too short; skipping file: " + path)
				failCount++
				return nil
			}
			if encrypt {
				out := path + ".aes"
				if !encryption.AES256EncryptFile(path, out, key) {
					failCount++
				} else {
					successCount++
				}
			} else {
				out := path + ".dec"
				if !encryption.AES256DecryptFile(path, out, key) {
					failCount++
				} else {
					successCount++
				}
			}

		default:
			utils.ErrorCout("Unknown cipher: " + cipher)
			failCount++
		}

		return nil
	})

	utils.SuccessCout("Directory processing completed. Success: " + strconv.Itoa(successCount) + " Failed: " + strconv.Itoa(failCount))
}

/* ---------- main ---------- */

func main() {
	utils.PrintBanner()
	utils.InfoCout("Author: pingplus/pingminus")
	utils.SuccessCout("Encrypter started successfully.")

	argc := len(os.Args)
	argv := os.Args

	/* ---------- single-arg commands ---------- */

	if argc == 2 {
		arg := argv[1]

		switch arg {
		case "--help", "-h", "/?", "help", "-help":
			utils.PlainCout("Usage: encrypter <filename> <action> <cipher> [options]")
			utils.PrintHelp()
			return

		case "--version", "-v", "version", "-version":
			utils.InfoCout("version 1.0")
			return

		case "--list-ciphers", "--list", "-l", "list":
			listCiphers()
			return
		}

		utils.ErrorCout("Unknown argument. Use --help.")
		return
	}

	/* ---------- minimal args ---------- */

	if argc < 4 {
		utils.ErrorCout("Not enough arguments provided. Use --help for more information.")
		return
	}

	filename := argv[1]
	action := argv[2]
	cipher := argv[3]

	encrypt := action == "--encrypt" || action == "e" || action == "--e"
	decrypt := action == "--decrypt" || action == "d" || action == "--d" 

	encryptDirFlag := action == "--encrypt-directory" || action == "ed" || action == "--ed"

	//not implemented yet
	decryptDirFlag := action == "--decrypt-directory" || action == "dd"

	// Directory flags imply mode
	if encryptDirFlag {
		encrypt = true
	}
	if decryptDirFlag {
		decrypt = true
	}
	

	if !encrypt && !decrypt && !encryptDirFlag && !decryptDirFlag {
		utils.ErrorCout("Invalid action provided. Use encrypt/decrypt.")
		return
	}

	/* ---------- path validation ---------- */

	if !pathExists(filename) {
		utils.ErrorCout("Input path does not exist.")
		return
	}

	if isDirectory(filename) {
		if !encryptDirFlag {
			utils.ErrorCout("Input is a directory. Use --encrypt-directory to encrypt directories.")
			return
		}
	} else {
		if !isRegularFile(filename) {
			utils.ErrorCout("Input is not a regular file.")
			return
		}
	}

	/* ---------- options ---------- */

	var (
		key        string
		outputFile string
		inplace    bool
	)

	for i := 4; i < argc; i++ {
		arg := argv[i]

		if arg == "--key" && i+1 < argc {
			i++
			key = argv[i]

		} else if arg == "--output" && i+1 < argc {
			i++
			outputFile = argv[i]

		} else if arg == "--inplace" {
			inplace = true

		} else {
			utils.ErrorCout("Unknown option: " + arg)
			return
		}
	}

	if key == "" && cipher != "caesar" {
		utils.ErrorCout("Missing encryption key.")
		return
	}

	if isDirectory(filename) && encryptDirFlag {
		encryptDirectory(filename, encrypt, cipher, key, outputFile)
		return
	}

	/* ---------- cipher dispatch ---------- */

	switch cipher {

	case "xor":
		if outputFile != "" && encrypt && !confirmOverwrite(outputFile) {
			utils.InfoCout("Operation cancelled.")
			return
		}

			if encrypt {
				encryption.EncryptXOR(filename, key, outputFile)
			} else {
				encryption.DecryptXOR(filename, key, outputFile)
			}

	case "caesar":
		shift, err := utils.ParseInt(key)
		if err != nil {
			utils.ErrorCout("Caesar cipher requires integer shift as key.")
			return
		}

		if outputFile != "" && encrypt && !confirmOverwrite(outputFile) {
			utils.InfoCout("Operation cancelled.")
			return
		}

		if encrypt {
			encryption.EncryptCaesar(filename, shift, outputFile)
		} else {
			encryption.DecryptCaesar(filename, shift, outputFile)
		}

	case "aes-256":
		if len(key) < 16 {
			utils.ErrorCout("AES key too short. Minimum 16 characters.")
			return
		}

		if outputFile == "" {
			if encrypt {
				outputFile = filename + ".aes"
			} else {
				outputFile = filename + ".dec"
			}
		}

		if !confirmOverwrite(outputFile) {
			utils.InfoCout("Operation cancelled.")
			return
		}
        

		success := false
		if encrypt {
			success = encryption.AES256EncryptFile(filename, outputFile, key)
		} else {
			success = encryption.AES256DecryptFile(filename, outputFile, key)
		}

		if !success {
			utils.ErrorCout("AES operation failed.")
			return
		}

		if inplace {
			if err := os.Remove(filename); err != nil {
				utils.ErrorCout("Failed to remove original file: " + err.Error())
				return
			}
			if err := os.Rename(outputFile, filename); err != nil {
				utils.ErrorCout("Failed to replace original file: " + err.Error())
				return
			}
			utils.SuccessCout("Replaced original with output file: " + filepath.Base(filename))
		} else {
			utils.SuccessCout("Output written to: " + filepath.Base(outputFile))
		}

	default:
		utils.ErrorCout("Unknown cipher. Use --list-ciphers.")
		return
	}
}
