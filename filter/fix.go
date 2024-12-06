package filter

import (
	"context"
	"github.com/gaarutyunov/osv-exporter/osv"
	"github.com/gaarutyunov/osv-exporter/re"
)

type fix struct {
}

func Fixed() Vulnerability {
	return &fix{}
}

func (c *fix) Filter(ctx context.Context, vulnerability *osv.Vulnerability) (bool, error) {
	for _, reference := range vulnerability.References {
		if re.GithubCommit.MatchString(reference.URL.String()) {
			return false, nil
		}
	}

	return true, nil
}
