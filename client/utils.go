package client // import "github.com/docker/docker/client"

import (
	"net/url"
	"regexp"

	"github.com/docker/docker/api/types/filters"
)

var headerRegexp *regexp.Regexp

// getDockerOS returns the operating system based on the server header from the daemon.
func getDockerOS(serverHeader string) string {
	if headerRegexp == nil {
		headerRegexp = regexp.MustCompile(`\ADocker/.+\s\((.+)\)\z`)
	}
	var osType string
	matches := headerRegexp.FindStringSubmatch(serverHeader)
	if len(matches) > 0 {
		osType = matches[1]
	}
	return osType
}

// getFiltersQuery returns a url query with "filters" query term, based on the
// filters provided.
func getFiltersQuery(f filters.Args) (url.Values, error) {
	query := url.Values{}
	if f.Len() > 0 {
		filterJSON, err := filters.ToJSON(f)
		if err != nil {
			return query, err
		}
		query.Set("filters", filterJSON)
	}
	return query, nil
}
