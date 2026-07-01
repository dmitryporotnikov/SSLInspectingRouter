package banner

import (
	"fmt"
	"io"
	"net"
	"net/http"
)

func PrintBanner() {
	banner := `
 _____ _____ __                                              
|   __|   __|  |                                             
|__   |__   |  |__                                           
|_____|_____|_____|                                          
                                                             
 _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ 
|     |   | |   __|  _  |   __|     |_   _|     |   | |   __|
|-   -| | | |__   |   __|   __|   --| | | |-   -| | | |  |  |
|_____|_|___|_____|__|  |_____|_____| |_| |_____|_|___|_____|
                                                             
 _____ _____ _____ _____ _____ _____                         
| __  |     |  |  |_   _|   __| __  |                        
|    -|  |  |  |  | | | |   __|    -|                        
|__|__|_____|_____| |_| |_____|__|__|                        
                                    
                                       
`
	fmt.Println("\033[36m" + banner + "\033[0m")
	fmt.Println("\033[33m" + "       GitHub: https://github.com/dmitryporotnikov/SSLInspectingRouter" + "\033[0m")
	fmt.Println()

	// Show the current ip addresses
	fmt.Println("Detected IP addresses:")
	ip, err := net.InterfaceAddrs()
	if err != nil {
		fmt.Println("Can't get IP addresses:", err)
		return
	}
	for _, addr := range ip {
		fmt.Println("\033[33m" + "\t" + addr.String() + "\033[0m")
	}
	fmt.Println()
	// Show public IP addresses
	fmt.Println("Public IP addresses:")
	resp, err := http.Get("https://api.ipify.org?format=text")
	if err != nil {
		fmt.Println("Can't get public IP addresses:", err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Can't read public IP addresses:", err)
		return
	}
	fmt.Println("\033[33m" + "\t" + string(body) + "\033[0m")
}
