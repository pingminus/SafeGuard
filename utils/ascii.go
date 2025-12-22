package utils

import "fmt"

// PrintBanner prints the ASCII banner
const (
    Reset  = "\033[0m"
    Red    = "\033[31m"
    Green  = "\033[32m"
    Yellow = "\033[33m"
    Blue   = "\033[34m"
    Purple = "\033[35m"
    Cyan   = "\033[36m"
    White  = "\033[37m"

    Bold   = "\033[1m"
)
func PrintBanner() {
    Banner := `
                _____                                    .___
  ___________ _/ ____\____   ____  __ _______ _______  __| _/
 /  ___/\__  \\   __\/ __ \ / ___\|  |  \__  \\_  __ \/ __ | 
 \___ \  / __ \|  | \  ___// /_/  >  |  // __ \|  | \/ /_/ | 
/____  >(____  /__|  \___  >___  /|____/(____  /__|  \____ | 
     \/      \/          \/_____/            \/           \/ 
`
    fmt.Println(Cyan + Bold + Banner + Reset)
}