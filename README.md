# KeyAuth-Go-Example : Please star 🌟
KeyAuth Go example for the https://keyauth.cc authentication system.

## **Bugs**

If the default example not added to your software isn't functioning how it should, please report a bug here https://keyauth.cc/app/?page=forms

However, we do **NOT** provide support for adding KeyAuth to your project. If you can't figure this out you should use Google or YouTube to learn more about the programming language you want to sell a program in.

## Copyright License

KeyAuth is licensed under **Elastic License 2.0**

* You may not provide the software to third parties as a hosted or managed
service, where the service provides users with access to any substantial set of
the features or functionality of the software.

* You may not move, change, disable, or circumvent the license key functionality
in the software, and you may not remove or obscure any functionality in the
software that is protected by the license key.

* You may not alter, remove, or obscure any licensing, copyright, or other notices
of the licensor in the software. Any use of the licensor’s trademarks is subject
to applicable law.

Thank you for your compliance, we work hard on the development of KeyAuth and do not appreciate our copyright being infringed.

## **What is KeyAuth?**

KeyAuth is an Open source authentication system with cloud hosting plans as well. Client SDKs available for [C#](https://github.com/KeyAuth/KeyAuth-CSHARP-Example), [C++](https://github.com/KeyAuth/KeyAuth-CPP-Example), [Python](https://github.com/KeyAuth/KeyAuth-Python-Example), [Java](https://github.com/KeyAuth-Archive/KeyAuth-JAVA-api), [JavaScript](https://github.com/mazkdevf/KeyAuth-JS-Example), [VB.NET](https://github.com/KeyAuth/KeyAuth-VB-Example), [PHP](https://github.com/KeyAuth/KeyAuth-PHP-Example), [Rust](https://github.com/KeyAuth/KeyAuth-Rust-Example), [Go](https://github.com/KeyAuth/KeyAuth-Go-Example), [Lua](https://github.com/mazkdevf/KeyAuth-Lua-Examples), [Ruby](https://github.com/mazkdevf/KeyAuth-Ruby-Example), and [Perl](https://github.com/mazkdevf/KeyAuth-Perl-Example). KeyAuth has several unique features such as memory streaming, webhook function where you can send requests to API without leaking the API, discord webhook notifications, ban the user securely through the application at your discretion. Feel free to join https://t.me/keyauth if you have questions or suggestions.

## **Customer connection issues?**

This is common amongst all authentication systems. Program obfuscation causes false positives in virus scanners, and with the scale of KeyAuth this is perceived as a malicious domain. So, `keyauth.com` and `keyauth.win` have been blocked by many internet providers. for dashbord, reseller panel, customer panel, use `keyauth.cc`

For API, `keyauth.cc` will not work because I purposefully blocked it on there so `keyauth.cc` doesn't get blocked also. So, you should create your own domain and follow this tutorial video https://www.youtube.com/watch?v=a2SROFJ0eYc. The tutorial video shows you how to create a domain name for 100% free if you don't want to purchase one.

## **How to compile?**

`go build .`

## **`KeyAuthApp` instance definition**

Visit https://keyauth.cc/app/ and select your application, then click on the **Go** tab

It'll provide you with the code which you should replace with in the `main.go` file.

```go
KeyAuthApp.Api(
    "example", // -- Application Name
    "JjPMBVlIOd", // -- Owner ID
    "db40d586f4b189e04e5c18c3c94b7e72221be3f6551995adc05236948d1762bc", // -- Application Secret
    "1.0", // -- Application Version
    "", // -- Token Path (PUT NULL OR LEAVE BLANK IF YOU DON'T WANT TO USE TOKEN SYSTEM)
)
```

## **Initialize application**

You don't need to add any code to initalize. KeyAuth will initalize when the instance definition is made.

If you edit the example, you can init it by running `KeyAuthApp.Init()`

## **Display application information**

```go
KeyAuthApp.FetchStats()
fmt.Println("\nApp Data:")
fmt.Println("Number of users: ", KeyAuthApp.NumUsers)
fmt.Println("Number of online users: ", KeyAuthApp.NumOnlineUsers)
fmt.Println("Number of keys: ", KeyAuthApp.NumKeys)
fmt.Println("Application Version: ", KeyAuthApp.Version)
fmt.Println("Customer panel link: ", KeyAuthApp.CustomerPanelURL)
```

## **Check session validation**

Use this to see if the user is logged in or not.

```go
fmt.Println("Current Session Validation Status: ", KeyAuthApp.Check())
```

## **Check blacklist status**

Check if HWID or IP Address is blacklisted. You can add this if you want, just to make sure nobody can open your program for less than a second if they're blacklisted. Though, if you don't mind a blacklisted user having the program for a few seconds until they try to login and register, and you care about having the quickest program for your users, you shouldn't use this function then. If a blacklisted user tries to login/register, the KeyAuth server will check if they're blacklisted and deny entry if so. So the check blacklist function is just auxiliary function that's optional.

```go
if KeyAuthApp.CheckBlack() {
    fmt.Println("You've been blacklisted from this application.")
    os.Exit(1)
}
```

## **Login with username/password**

```go
func Input(message string) string {
  	fmt.Print(message)
  
  	var input string
  	fmt.Scanln(&input)
  	return input
}

username := Input("Input username: ")
password := Input("Input password: ")

KeyAuthApp.Login(username, password)
```

## **Register with username/password/key**

```go
func Input(message string) string {
  	fmt.Print(message)
  
  	var input string
  	fmt.Scanln(&input)
  	return input
}

username := Input("Input username: ")
password := Input("Input password: ")
license := Input("Input license: ")

KeyAuthApp.Register(username, password, license)
```

## **Upgrade user username/key**

Used so the user can add extra time to their account by claiming new key.

> **Warning**
> No password is needed to upgrade account. So, unlike login, register, and license functions - you should **not** log user in after successful upgrade.

```go
func Input(message string) string {
  	fmt.Print(message)
  
  	var input string
  	fmt.Scanln(&input)
  	return input
}

username := Input("Input username: ")
license := Input("Input license: ")

KeyAuthApp.Upgrade(username, license)
```

## **Login with just license key**

Users can use this function if their license key has never been used before, and if it has been used before. So if you plan to just allow users to use keys, you can remove the login and register functions from your code.

```go
func Input(message string) string {
  	fmt.Print(message)
  
  	var input string
  	fmt.Scanln(&input)
  	return input
}

license := Input("Input license: ")

KeyAuthApp.License(license)
```

## **User Data**

Show information for current logged-in user.

```go
fmt.Println("\nUser Data:")
fmt.Println("   Username: ", KeyAuthApp.Username)
fmt.Println("   IP Address: ", KeyAuthApp.IP)
fmt.Println("   HWID: ", KeyAuthApp.HWID)
fmt.Println("   Created At: ", KeyAuthApp.CreatedDate)
fmt.Println("   Last Login At: ", KeyAuthApp.LastLogin)
fmt.Println("   Subscription: ", KeyAuthApp.Subscription)
fmt.Println("Current Session Validation Status: ", KeyAuthApp.Check())
```

## **Show list of online users**

```go
  	onlineUsers := KeyAuthApp.fetchOnline()
  	OU := ""
  	if onlineUsers == nil {
  		  OU = "No online users"
  	} else {
  		  for i := 0; i < len(onlineUsers); i++ {
  			  OU += onlineUsers[i]["credential"].(string) + " "
  		  }
  	}
  	fmt.Println("\n" + OU + "\n")
```

## **Application variables**

A string that is kept on the server-side of KeyAuth. On the dashboard you can choose for each variable to be authenticated (only logged in users can access), or not authenticated (any user can access before login). These are global and static for all users, unlike User Variables which will be dicussed below this section.

```go
* Get normal variable and print it
data := KeyAuthApp.Var("varName")
fmt.Println(data)
```

## **User Variables**

User variables are strings kept on the server-side of KeyAuth. They are specific to users. They can be set on Dashboard in the Users tab, via SellerAPI, or via your loader using the code below. `discord` is the user variable name you fetch the user variable by. `test#0001` is the variable data you get when fetching the user variable.

```go
* Set up user variable
KeyAuthApp.Setvar("varName", "varValue")
```

And here's how you fetch the user variable:

```go
* Get user variable and print it
data := KeyAuthApp.Getvar("varName")
fmt.Println(data)
```

## **Application Logs**

Can be used to log data. Good for anti-debug alerts and maybe error debugging. If you set Discord webhook in the app settings of the Dashboard, it will send log messages to your Discord webhook rather than store them on site. It's recommended that you set Discord webhook, as logs on site are deleted 1 month after being sent.

You can use the log function before login & after login.

```go
* Log message to the server and then to your webhook what is set on app settings
KeyAuthApp.Log("Message")
```

## **Ban the user**

Ban the user and blacklist their HWID and IP Address. Good function to call upon if you use anti-debug and have detected an intrusion attempt.

Function only works after login.

```go
KeyAuthApp.Ban()
```

## **Logout session**

Logout the users session and close the application. 

This only works if the user is authenticated (logged in)
```go
KeyAuthApp.Logout()
```

## **Server-sided webhooks**

Tutorial video https://www.youtube.com/watch?v=ENRaNPPYJbc

> **Note**
> Read documentation for KeyAuth webhooks here https://keyauth.readme.io/reference/webhooks-1

Send HTTP requests to URLs securely without leaking the URL in your application. You should definitely use if you want to send requests to SellerAPI from your application, otherwise if you don't use you'll be leaking your seller key to everyone. And then someone can mess up your application.

1st example is how to send request with no POST data. just a GET request to the URL. `7kR0UedlVI` is the webhook ID, `https://keyauth.win/api/seller/?sellerkey=sellerkeyhere&type=black` is what you should put as the webhook endpoint on the dashboard. This is the part you don't want users to see. And then you have `&ip=1.1.1.1&hwid=abc` in your program code which will be added to the webhook endpoint on the keyauth server and then the request will be sent.

2nd example includes post data. it is form data. it is an example request to the KeyAuth API. `7kR0UedlVI` is the webhook ID, `https://keyauth.win/api/1.2/` is the webhook endpoint.

3rd examples included post data though it's JSON. It's an example reques to Discord webhook `7kR0UedlVI` is the webhook ID, `https://discord.com/api/webhooks/...` is the webhook endpoint.

```go
* example to send normal request with no POST data
data := KeyAuthApp.Webhook("7kR0UedlVI", "?ip=1.1.1.1&hwid=abc")

* example to send form data
data := KeyAuthApp.Webhook("7kR0UedlVI", "", "type=init&name=test&ownerid=j9Gj0FTemM", "application/x-www-form-urlencoded")

* example to send JSON
data := KeyAuthApp.Webhook("7kR0UedlVI", "", "{\"content\": \"webhook message here\",\"embeds\": null}", "application/json")
```

## **Download file**

> **Note**
> Read documentation for KeyAuth files here https://docs.keyauth.cc/website/dashboard/files

Keep files secure by providing KeyAuth your file download link on the KeyAuth dashboard. Make sure this is a direct download link (as soon as you go to the link, it starts downloading without you clicking anything). The KeyAuth download function provides the bytes, and then you get to decide what to do with those. This example shows how to write it to a file named `text.txt` in the same folder as the program, though you could execute with RunPE or whatever you want.

`385624` is the file ID you get from the dashboard after adding file.

```go
* Download Files form the server to your computer using the download function in the api class
bytes, err := KeyAuthApp.File("385624")
if err != nil {
    panic(err)
}

err = ioutil.WriteFile("example.exe", bytes, 0644)
if err != nil {
    panic(err)
}
```

## **Chat channels**

Allow users to communicate amongst themselves in your program.

Example from the form example on how to fetch the chat messages.

```go
* Get chat messages
messages := keyauthapp.chatGet("CHANNEL")
Messages := ""
for i := 0; i < len(messages); i++ {
    timestamp := time.Unix(int64(messages[i]["timestamp"]), 0)
		Messages += timestamp.UTC().Format("2006-01-02 15:04:05") + " - " + messages[i]["author"] + ": " + messages[i]["message"] + "\n"
}
fmt.Println("\n\n" + Messages)
```

Example on how to send chat message.

```go
* Send chat message
KeyAuthApp.ChatSend("MESSAGE", "CHANNEL")
```

Looking for a Discord bot made by the KeyAuth & RestoreCord founder that you can use to backup your Discord members, server settings, and messages? Go to https://vaultcord.com
