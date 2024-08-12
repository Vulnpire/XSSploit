is an automated tool designed for generating and injecting Cross-Site Scripting (XSS) payloads into URLs.

## Features

* Automated Payload Generation: Generates random XSS payloads using a combination of common HTML tags, JavaScript events, and code snippets.
* Multi-URL Injection: Easily injects payloads into multiple URLs, streamlining the process of vulnerability testing.
* Verbose Output: An optional --verbose flag provides detailed output, including the original and injected URLs.
* Customizable Payload Count: Specify the number of XSS payloads to generate and inject per URL.

## Installation

- Clone the repository:

`git clone https://github.com/Vulnpire/XSSploit`

- Build the tool:

`go build -o xssploit main.go`

- Run the tool:

./Arguments

    -file: Path to a .txt file containing URLs to inject the payloads into. Each URL should be on a new line.
    -number: Number of XSS payloads to generate for each URL.

## Arguments

    -file: Path to a .txt file containing URLs to inject the payloads into. Each URL should be on a new line.
    -number: Number of XSS payloads to generate for each URL.

## Example

    » ./xssploit -number 2 -file urls.txt
    
    http://example.com/?param=<script onclick="alert(1)" style="color:12px;">
    http://example.com/?param=<img onerror="console.log("XSS")" style="height:42px;">
