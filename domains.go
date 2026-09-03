package warnlist

import (
	"bufio"
	"fmt"
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

// domainsFromSource opens the configured source and streams its domains, one
// per channel message, each normalised to a fully qualified name with a
// trailing dot. Opening the source is synchronous so that an unreadable file,
// an unreachable URL or a non-200 response is reported to the caller instead
// of silently producing an empty warnlist; only the line-by-line scan runs in
// the background.
func domainsFromSource(source string, sourceType string, sourceFormat string) (chan string, error) {
	var sourceData io.Reader
	var closer io.Closer

	switch sourceType {
	case DomainSourceTypeFile:
		log.Infof("Loading from file: %s", source)
		file, err := os.Open(source) // nolint: gosec
		if err != nil {
			return nil, err
		}
		sourceData, closer = file, file
	case DomainSourceTypeURL:
		log.Infof("Loading from URL: %s", source)
		resp, err := http.Get(source) // nolint: gosec
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("fetching %s: unexpected status %s", source, resp.Status)
		}
		sourceData, closer = resp.Body, resp.Body
	default:
		return nil, fmt.Errorf("unknown source type: %s", sourceType)
	}

	c := make(chan string)
	go func() {
		defer close(c)
		defer closer.Close() //nolint:errcheck

		scanner := bufio.NewScanner(sourceData)
		for scanner.Scan() {
			domain := strings.TrimSpace(scanner.Text())
			if domain == "" || strings.HasPrefix(domain, "#") {
				// Skip empty and comment lines
				continue
			}

			if sourceFormat == DomainFileFormatHostfile {
				// Hostfile format:   127.0.0.1  some.host
				fields := strings.Fields(domain)
				if len(fields) < 2 {
					log.Warningf("skipping malformed hostfile line: %q", domain)
					continue
				}
				domain = fields[1]
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

	return c, nil
}
