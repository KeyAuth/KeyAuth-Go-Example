package main

import (
	KeyAuthApp "KeyAuth/KeyAuth"
	"fmt"
	"os"
	"strconv"
	"time"
)

func Input(message string) string {
	fmt.Print(message)

	var input string
	fmt.Scanln(&input)
	return input
}

func UnixToReadable(unixTimestamp string) string {
	timestamp, err := strconv.ParseInt(unixTimestamp, 10, 64)
	if err != nil {
		return unixTimestamp // Return original if parsing fails
	}
	t := time.Unix(timestamp, 0).UTC()
	return t.Format("2006-01-02 15:04:05")
}

func printUserData() {
	fmt.Println("\nUser Data:")
	fmt.Println("   Username: ", KeyAuthApp.Username)
	fmt.Println("   IP Address: ", KeyAuthApp.IP)
	fmt.Println("   HWID: ", KeyAuthApp.HWID)
	fmt.Println("   Created At: ", UnixToReadable(KeyAuthApp.CreatedDate))
	fmt.Println("   Last Login At: ", UnixToReadable(KeyAuthApp.LastLogin))
	fmt.Println("   Subscription Expiry: ", UnixToReadable(KeyAuthApp.Expires))
	fmt.Println("   Subscription: ", KeyAuthApp.Subscription)
}

func showMenu() {
	fmt.Println("[1] Login")
	fmt.Println("[2] Register")
	fmt.Println("[3] Upgrade")
	fmt.Println("[4] License Only Login")
}

func main() {
	KeyAuthApp.Api(
		"",    // -- Application Name
		"", // -- Owner ID
		"1.0",        // -- Application Version
		"",           // -- Token Path (PUT NULL OR LEAVE BLANK IF YOU DON'T WANT TO USE TOKEN SYSTEM)
	)

	done := false
	for !done {
		if KeyAuthApp.LockoutActive() {
			fmt.Printf("Locked out. Try again in %d ms\n", KeyAuthApp.LockoutRemainingMs())
			KeyAuthApp.CloseDelay()
			os.Exit(1)
		}

		showMenu()
		ans := Input("\nChoose your option: ")

		switch ans {
		case "1":
			username := Input("Input username: ")
			password := Input("Input password: ")
			KeyAuthApp.Login(username, password)
			printUserData()
			KeyAuthApp.ResetLockout()
			done = true
		case "2":
			username := Input("Input username: ")
			password := Input("Input password: ")
			license := Input("Input license: ")
			KeyAuthApp.Register(username, password, license)
			printUserData()
			KeyAuthApp.ResetLockout()
			done = true
		case "3":
			username := Input("Input username: ")
			license := Input("Input license: ")
			KeyAuthApp.Upgrade(username, license)
			printUserData()
			KeyAuthApp.ResetLockout()
			done = true
		case "4":
			license := Input("Input license: ")
			KeyAuthApp.License(license)
			printUserData()
			KeyAuthApp.ResetLockout()
			done = true
		default:
			fmt.Println("Invalid option")
			KeyAuthApp.BadInputDelay()
		}
	}

	fmt.Println("\nExiting application in 10 seconds...")
	time.Sleep(10 * time.Second)
	os.Exit(0)
}
