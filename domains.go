package warnlist

import (
	"bufio"
	"io"
	"net/http"
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
			// Clean the path
			cleanPath := filepath.Clean(source)
			if info, err := os.Stat(cleanPath); err != nil || info.IsDir() {
				log.Error(err)
				return
			}

			file, err := os.Open(cleanPath)
			if err != nil {
				log.Error(err)
				return
			}
			defer file.Close() // nolint: errcheck
			sourceData = file
		case DomainSourceTypeURL:
			// TODO
			log.Infof("Loading from URL: %s", source)
			// Load the domain list from the URL
			resp, err := http.Get(source) // nolint: gosec
			if err != nil {
				log.Error(err)
			}
			defer resp.Body.Close() // nolint: errcheck
			sourceData = resp.Body
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
