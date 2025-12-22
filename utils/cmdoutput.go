package utils

import "fmt"

func InfoCout(msg string) {
	fmt.Printf("\033[34m[i]\033[0m %s\n", msg)
}
func ErrorCout(msg string) {
	fmt.Printf("\033[31m[-]\033[0m %s\n", msg)
}
func SuccessCout(msg string) {
	fmt.Printf("\033[32m[+]\033[0m %s\n", msg)
}
func WarningCout(msg string) {
	fmt.Printf("\033[33m[!]\033[0m %s\n", msg)
}
func DebugCout(msg string) {
	fmt.Printf("\033[35m[*]\033[0m %s\n", msg)
}
func QuestionCout(msg string) {
	fmt.Printf("\033[36m[?]\033[0m %s\n", msg)
}
func PlainCout(msg string) {
	fmt.Printf("%s\n", msg)
}


func PrintHelp() {
	PlainCout("Usage: encrypter <filename> <action> <cipher> [options]")
	PlainCout("")
	PlainCout("Actions:")
	PlainCout("  --encrypt, e       Encrypt the file")
	PlainCout("  --encrypt-directory, ed       Encrypt the directory")

	PlainCout("  --decrypt, d       Decrypt the file")
	PlainCout("")
	PlainCout("Ciphers:")
	PlainCout("  caesar             Caesar cipher")
	PlainCout("  xor                XOR cipher")
	PlainCout("  aes                AES encryption")
	PlainCout("")
	PlainCout("Options:")
	PlainCout("  --key <key>       Specify the encryption/decryption key (not needed for caesar)")
	PlainCout("  --output <file>   Specify the output file name")
	PlainCout("  --inplace <file>   encrypt the file in place (NOTICE: CAUTION ADVISED!)")
	PlainCout("")
}