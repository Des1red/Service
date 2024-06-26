package main

import (
	"fmt"
	"github.com/Des1red/myservice/protocols"
	"strconv"
)


func menu() int {
	fmt.Println(`
 __  __        _____                _          
|  \/  |      / ____|              (_)         
| \  / |_   _| (___   ___ _ ____   ___  ___ ___ 
| |\/| | | | |\___ \ / _ \ '__\ \ / / |/ __/ _ \
| |  | | |_| |____) |  __/ |   \ V /| | (_|  __/
|_|  |_|\__, |_____/ \___|_|    \_/ |_|\___\___|
         __/ |                                  
        |___/                                   
	`)
	fmt.Println("\n1. FTPS    2. SFTP    3. SSH    4.HTTPS    0. EXIT")

	// Map of valid options
	validOptions := map[int]bool{
		1: true,
		2: true,
		3: true,
		4: true,
		0: true,
		// Add more options here as needed
	}

	var service string
	for {
		fmt.Print("Choose an option (number): ")
		fmt.Scanln(&service)
		choice, err := strconv.Atoi(service)

		if err != nil {
			fmt.Println("Invalid input. Please provide a number.")
			continue
		}

		if validOptions[choice] {
			return choice
		} else {
			fmt.Println("Invalid option, please choose again.")
		}
	}
}

func main() {
	
	for {
		service := menu()
		fmt.Printf("You selected option %d\n", service)

		if service == 1 {
			protocols.Ftps()
		}

		if service == 2 {
			protocols.Sftp()
		}

		if service == 3 {
			protocols.SSH()
		}

		if service == 4 {
			protocols.Https()
		}
		
		if service == 0 {
			break
		}
	}
}
