package warnlist

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	DomainFileFormatHostfile = "hostfile"
	DomainFileFormatTextList = "text"
	DomainSourceTypeFile     = "file"
	DomainSourceTypeURL      = "url"
)

func domainsFromSource(source string, sourceType string, sourceFormat string) chan string {

	c := make(chan string)

	go func() {
		defer close(c)

		var sourceData io.Reader

		switch sourceType {
		case DomainSourceTypeFile:
			log.Infof("Loading from file: %s", source)
			file, err := openSafeFile(source)
			if err != nil {
				log.Error(err)
				return
			}
			defer file.Close()
			sourceData = file
		case DomainSourceTypeURL:
			// TODO
			log.Infof("Loading from URL: %s", source)

			body, err := fetchFromSafeURL(source)
			if err != nil {
				log.Error(err)
				return
			}
			defer body.Close()
			sourceData = body
		}

		scanner := bufio.NewScanner(sourceData)
		for scanner.Scan() {
			domain := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(domain, "#") {
				// Skip comment lines
				continue
			}

			if domain == "" {
				// Skip empty lines
				continue
			}

			if sourceFormat == DomainFileFormatHostfile {
				domain = strings.Fields(domain)[1] // Assumes hostfile format:   127.0.0.1  some.host
			}

			// Assume all domains are global origin, with trailing dot (e.g. example.com.)
			if !strings.HasSuffix(domain, ".") {
				domain += "."
			}

			c <- domain
		}
		if err := scanner.Err(); err != nil {
			log.Error(err)
		}
	}()

	return c

}

// openSafeFile validates and safely opens a file
func openSafeFile(filePath string) (io.ReadCloser, error) {
	// Convert to absolute path
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("invalid file path: %w", err)
	}

	file, err := os.Open(absPath)
	if err != nil {
		return nil, err
	}

	return file, nil
}

// fetchFromSafeURL validates the URL and fetches content
func fetchFromSafeURL(rawURL string) (io.ReadCloser, error) {
	// Validate URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Only allow http and https schemes
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme: %s", parsedURL.Scheme)
	}

	// Fetch from URL
	resp, err := http.Get(rawURL) // nolint:gosec
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return resp.Body, nil
}
