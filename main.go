package main

import (
	"bufio"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

//go:embed patterns.txt
var defaultPatterns string

const (
	timeout   = 15 * time.Second
	maxBytes  = 5 * 1024 * 1024
	userAgent = "DarkMystery/0.2"
)

type Pattern struct {
	Name  string
	Regex *regexp.Regexp
}

type NoRedirectError struct{}

func (NoRedirectError) Error() string {
	return "redirect stopped"
}

func parsePatterns(reader io.Reader, path string) ([]Pattern, []string, error) {
	var patterns []Pattern
	var errs []string

	scanner := bufio.NewScanner(reader)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if !strings.Contains(line, "|") {
			errs = append(errs, fmt.Sprintf(
				"%s:%d: missing '|' separator", path, lineNumber))
			continue
		}

		name, expression, _ := strings.Cut(line, "|")
		name = strings.TrimSpace(name)
		expression = strings.TrimSpace(expression)

		if name == "" || expression == "" {
			errs = append(errs, fmt.Sprintf(
				"%s:%d: missing rule name or regex", path, lineNumber))
			continue
		}

		// Convert Python-style non-capturing groups to Go-compatible groups.
		expression = strings.ReplaceAll(expression, "(?:", "(")

		re, err := regexp.Compile(expression)
		if err != nil {
			errs = append(errs, fmt.Sprintf(
				"%s:%d [%s]: invalid regex: %v",
				path, lineNumber, name, err))
			continue
		}

		patterns = append(patterns, Pattern{Name: name, Regex: re})
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}

	return patterns, errs, nil
}

func loadPatterns(path string) ([]Pattern, []string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	return parsePatterns(file, path)
}

func fetchURL(url string, quiet bool) (string, bool, error) {
	client := &http.Client{Timeout: timeout}

	if quiet {
		client.CheckRedirect = func(
			req *http.Request, via []*http.Request,
		) error {
			return http.ErrUseLastResponse
		}
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		var redirectErr NoRedirectError
		if errors.As(err, &redirectErr) {
			return "", false, nil
		}
		return "", false, err
	}
	defer resp.Body.Close()

	if quiet && resp.StatusCode != http.StatusOK {
		return "", false, nil
	}

	if !quiet && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		if resp.StatusCode == 403 || resp.StatusCode == 404 {
			return "", false, nil
		}
		fmt.Fprintf(os.Stderr, "[!] HTTP %d: %s\n", resp.StatusCode, url)
		return "", false, nil
	}

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if contentType != "" &&
		!strings.Contains(contentType, "javascript") &&
		!strings.Contains(contentType, "ecmascript") &&
		!strings.Contains(contentType, "text/") &&
		!strings.Contains(contentType, "json") {
		fmt.Fprintf(os.Stderr, "[!] Skipping non-text content: %s\n", url)
		return "", true, nil
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return "", false, err
	}
	if len(data) > maxBytes {
		fmt.Fprintf(os.Stderr, "[!] Response exceeded size limit: %s\n", url)
		data = data[:maxBytes]
	}

	return string(data), true, nil
}

const version = "v0.1.0"

func run() int {
	executable := "dmyst"

	flags := flag.NewFlagSet(executable, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	patternPath := flags.String("p", "", "Use a custom pattern file instead of built-in defaults")
	flags.StringVar(patternPath, "patterns", "", "Use a custom pattern file instead of built-in defaults")

	outputPath := flags.String("o", "", "Save findings to a file")
	flags.StringVar(outputPath, "output", "", "Save findings to a file")

	quiet := flags.Bool("q", false, "Scan only HTTP 200 URLs; silently ignore other HTTP statuses")
	flags.BoolVar(quiet, "quiet-errors", false, "Scan only HTTP 200 URLs; silently ignore other HTTP statuses")

	unique := flags.Bool("u", false, "Show globally unique findings")
	flags.BoolVar(unique, "unique", false, "Show globally unique findings")

	checkPatterns := flags.Bool("check-patterns", false, "Validate pattern syntax without scanning URLs")
	showVersion := flags.Bool("v", false, "Show version information")
	flags.BoolVar(showVersion, "version", false, "Show version information")

	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, "DARK MYSTERY — Uncover what hides in the source.")
		fmt.Fprintln(os.Stderr, "\nUsage:")
		fmt.Fprintln(os.Stderr, "  dmyst [options] < urls.txt")
		fmt.Fprintln(os.Stderr, "\nOptions:")
		fmt.Fprintln(os.Stderr, "  -p, --patterns FILE   Use a custom pattern file")
		fmt.Fprintln(os.Stderr, "  -o, --output FILE     Save findings to a file")
		fmt.Fprintln(os.Stderr, "  -q, --quiet-errors    Scan only HTTP 200 responses")
		fmt.Fprintln(os.Stderr, "  -u, --unique          Show globally unique findings")
		fmt.Fprintln(os.Stderr, "      --check-patterns  Validate patterns without scanning")
		fmt.Fprintln(os.Stderr, "  -h, --help            Show this help message")
		fmt.Fprintln(os.Stderr, "  -v, --version         Show version information")
	}

	if err := flags.Parse(os.Args[1:]); err != nil {
		return 2
	}

	if *showVersion {
		fmt.Printf("DARK MYSTERY %s\n", version)
		return 0
	}

	// Use embedded defaults unless the user specifies a custom file.
	var patterns []Pattern
	var patternErrors []string
	var err error

	if *patternPath != "" {
		patterns, patternErrors, err = loadPatterns(*patternPath)
	} else {
		patterns, patternErrors, err = parsePatterns(
			strings.NewReader(defaultPatterns), "embedded patterns")
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "dmyst: %v\n", err)
		return 2
	}

	if *checkPatterns {
		for _, errText := range patternErrors {
			fmt.Fprintf(os.Stderr, "[FAIL] %s\n", errText)
		}
		if len(patternErrors) > 0 || len(patterns) == 0 {
			if len(patterns) == 0 && len(patternErrors) == 0 {
				fmt.Fprintln(os.Stderr, "[FAIL] No patterns found.")
			}
			return 1
		}
		fmt.Printf("[PASS] All %d patterns are valid.\n", len(patterns))
		return 0
	}

	for _, errText := range patternErrors {
		fmt.Fprintf(os.Stderr, "[!] %s\n", errText)
	}
	if len(patterns) == 0 {
		fmt.Fprintln(os.Stderr, "dmyst: No valid patterns loaded.")
		return 2
	}

	info, err := os.Stdin.Stat()
	if err == nil && (info.Mode()&os.ModeCharDevice) != 0 {
		flags.Usage()
		return 0
	}

        fmt.Fprintf(os.Stderr, "[*] Loaded %d patterns\n", len(patterns))


	var output *os.File
	if *outputPath != "" {
		output, err = os.OpenFile(
			*outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dmyst: Cannot open output file: %v\n", err)
			return 2
		}
		defer output.Close()
	}

	urlsSeen := 0
	matchesSeen := 0
	uniqueFindings := make(map[string]struct{})

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url == "" || strings.HasPrefix(url, "#") {
			continue
		}
		if !strings.HasPrefix(url, "https://") &&
			!strings.HasPrefix(url, "http://") {
			fmt.Fprintf(os.Stderr, "[!] Skipping invalid URL: %s\n", url)
			continue
		}

		urlsSeen++
		source, scanned, err := fetchURL(url, *quiet)
		if err != nil {
			if !*quiet {
				fmt.Fprintf(os.Stderr, "[!] Fetch failed: %v\n", err)
			}
			continue
		}
		if !scanned {
			continue
		}

		fmt.Fprintf(os.Stderr, "\n[+] Scanned: %s\n", url)
		urlHasFindings := false

		for _, pattern := range patterns {
			for _, match := range pattern.Regex.FindAllString(source, -1) {
				matchesSeen++

				value := strings.ReplaceAll(match, "\n", "\\n")
				if len(value) > 300 {
					value = value[:300] + "..."
				}

				key := pattern.Name + "\x00" + match
				_, duplicate := uniqueFindings[key]
				uniqueFindings[key] = struct{}{}

				if *unique && duplicate {
					continue
				}

				result := fmt.Sprintf(" %s\t%s", pattern.Name, value)

				if output != nil {
					if !urlHasFindings {
						fmt.Fprintf(output, "\n[+] Scanned: %s\n", url)
						urlHasFindings = true
					}
					fmt.Fprintln(output, result)
				}

				fmt.Println(result)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Input error: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr,
		"\n[*] Scan complete | URLs: %d | Matches: %d | Unique findings: %d\n",
		urlsSeen, matchesSeen, len(uniqueFindings))

	return 0
}

func main() {
	os.Exit(run())
}
