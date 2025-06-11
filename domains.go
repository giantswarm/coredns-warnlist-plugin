package warnlist

import (
	"bufio"
	"io"
	"net/http"
	"os"
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
			file, err := os.Open(source) // nolint: gosec
			if err != nil {
				log.Error(err)
				return
			}
			defer file.Close() //nolint: errcheck
			sourceData = file
		case DomainSourceTypeURL:
			log.Infof("Loading from URL: %s", source)
			resp, err := http.Get(source) // nolint: gosec
			if err != nil {
				log.Error(err)
				return
			}
			defer resp.Body.Close()
			sourceData = resp.Body // nolint: errcheck
		default:
			log.Errorf("Unknown source type: %s", sourceType)
			return
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
