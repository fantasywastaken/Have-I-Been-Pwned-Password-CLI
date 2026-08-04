package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
)

var hibpBase = buildURL()

func buildURL() string {
	slash := string([]byte{'/', '/'})
	return "https:" + slash + "api.pwnedpasswords.com/range/"
}

type pwResult struct {
	Password string
	Count    int
	Error    string
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "check":
		runCheck(os.Args[2:])
	case "file":
		runFile(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println("Have-I-Been-Pwned Password CLI")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  hibp check <password>          check a single password")
	fmt.Println("  hibp file  <path>              check every password in the file (one per line)")
	fmt.Println()
	fmt.Println("Notes:")
	fmt.Println("  Only the first 5 characters of the SHA-1 hash leave your machine (k-anonymity).")
}

func runCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	timeout := fs.Duration("timeout", 10*time.Second, "HTTP timeout")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: hibp check <password>")
		os.Exit(1)
	}
	client := &http.Client{Timeout: *timeout}
	res := checkPassword(client, fs.Arg(0))
	printResult(res)
	if res.Error != "" {
		os.Exit(2)
	}
	if res.Count > 0 {
		os.Exit(1)
	}
}

func runFile(args []string) {
	fs := flag.NewFlagSet("file", flag.ExitOnError)
	timeout := fs.Duration("timeout", 10*time.Second, "HTTP timeout per request")
	delay := fs.Duration("delay", 150*time.Millisecond, "delay between requests")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: hibp file <path>")
		os.Exit(1)
	}

	f, err := os.Open(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	client := &http.Client{Timeout: *timeout}
	scanner := bufio.NewScanner(f)
	total, pwned, errored := 0, 0, 0
	first := true
	for scanner.Scan() {
		p := strings.TrimRight(scanner.Text(), "\r\n")
		if p == "" {
			continue
		}
		if !first && *delay > 0 {
			time.Sleep(*delay)
		}
		first = false
		total++
		res := checkPassword(client, p)
		printResult(res)
		if res.Error != "" {
			errored++
			continue
		}
		if res.Count > 0 {
			pwned++
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
	}

	summary := color.New(color.Bold).SprintFunc()
	fmt.Println()
	fmt.Printf("%s total=%d pwned=%d safe=%d errors=%d\n",
		summary("Summary:"), total, pwned, total-pwned-errored, errored)
	if pwned > 0 {
		os.Exit(1)
	}
	if errored > 0 {
		os.Exit(2)
	}
}

func checkPassword(client *http.Client, password string) pwResult {
	res := pwResult{Password: password}
	sum := sha1.Sum([]byte(password))
	hashStr := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix := hashStr[:5]
	suffix := hashStr[5:]

	req, err := http.NewRequest(http.MethodGet, hibpBase+prefix, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	req.Header.Set("User-Agent", "hibp-password-cli/1.0")
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("Accept", "text/plain")

	resp, err := client.Do(req)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		res.Error = fmt.Sprintf("HIBP returned status %d", resp.StatusCode)
		return res
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		res.Error = err.Error()
		return res
	}

	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if !strings.EqualFold(parts[0], suffix) {
			continue
		}
		n, convErr := strconv.Atoi(strings.TrimSpace(parts[1]))
		if convErr != nil {
			continue
		}
		res.Count = n
		return res
	}
	return res
}

func printResult(r pwResult) {
	red := color.New(color.FgRed, color.Bold).SprintFunc()
	green := color.New(color.FgGreen, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow, color.Bold).SprintFunc()

	label := fmt.Sprintf("%-14s", mask(r.Password))
	if r.Error != "" {
		fmt.Printf("%s %s %s\n", label, red("ERROR"), r.Error)
		return
	}
	if r.Count > 0 {
		fmt.Printf("%s %s seen %s times in breach corpora\n",
			label, red("PWNED"), yellow(strconv.Itoa(r.Count)))
		return
	}
	fmt.Printf("%s %s not found in HIBP corpus\n", label, green("SAFE"))
}

func mask(s string) string {
	if s == "" {
		return "(empty)"
	}
	if len(s) <= 2 {
		return strings.Repeat("*", len(s))
	}
	return string(s[0]) + strings.Repeat("*", len(s)-2) + string(s[len(s)-1])
}
