package main

import (
    KeyAuthApp "KeyAuth/KeyAuth"
    "fmt"
    "os"
	"time"
)

func Input(message string) string {
	fmt.Print(message)

	var input string
	fmt.Scanln(&input)
	return input
}

func main() {
    KeyAuthApp.Api(
        "", // -- Application Name
        "", // -- Owner ID
        "", // -- Application Secret
        "", // -- Application Version
        "", // -- Token Path (PUT NULL OR LEAVE BLANK IF YOU DON'T WANT TO USE TOKEN SYSTEM)
    )

    fmt.Println("[1] Login")
    fmt.Println("[2] Register")
    fmt.Println("[3] Upgrade")
    fmt.Println("[4] License Only Login")

    ans := Input("\nChoose your option: ")
    
    if ans == "1" {
        username := Input("Input username: ")
        password := Input("Input password: ")

        KeyAuthApp.Login(username, password)
    } else if ans == "2" {
        username := Input("Input username: ")
        password := Input("Input password: ")
        license := Input("Input license: ")

        KeyAuthApp.Register(username, password, license)
    } else if ans == "3" {
        username := Input("Input username: ")
        license := Input("Input license: ")

        KeyAuthApp.Upgrade(username, license)
    } else if ans == "4" {
        license := Input("Input license: ")

        KeyAuthApp.License(license)
    } else {
        fmt.Println("Invalid option")
        time.Sleep(2 * time.Second)
        main()
    }

    fmt.Println("\nUser Data:")
    fmt.Println("   Username: ", KeyAuthApp.Username)
    fmt.Println("   IP Address: ", KeyAuthApp.IP)
    fmt.Println("   HWID: ", KeyAuthApp.HWID)
    fmt.Println("   Created At: ", KeyAuthApp.CreatedDate)
    fmt.Println("   Last Login At: ", KeyAuthApp.LastLogin)
    fmt.Println("   Subscription: ", KeyAuthApp.Subscription)

    fmt.Println("\nExiting application in 10 seconds...")
    time.Sleep(10 * time.Second)
    os.Exit(0)
}
