package malicious

import (
	"bufio"
	"io"
	"os"
	"strings"
)

const (
	DomainFileFormatHostfile = "hostfile"
	DomainFileFormatTextList = "text"
	DomainSourceTypeFile     = "file"
	DomainSourceTypeURL      = "url"
)

func domainsGenerator(source string, sourceType string, sourceFormat string) chan string {

	c := make(chan string)

	go func() {
		defer close(c)
		// TODO: handle URL vs file
		// if sourceType == DomainSourceTypeFile {

		// } else if sourceType == DomainSourceTypeURL {
		// 	// TODO

		// }

		sourceData, err := os.Open(source)
		if err != nil {
			log.Error(err)
		}
		defer sourceData.Close()

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
			// log.Info("Adding ", domain, " to domain blacklist")
			c <- domain
		}
		if err := scanner.Err(); err != nil {
			log.Error(err)
		}
		// close(c)
	}()

	return c

}

func domainsFromFile(file io.Reader, fileType string) []string {
	return []string{}
}
