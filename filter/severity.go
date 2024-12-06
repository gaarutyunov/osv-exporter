package filter

import (
	"context"
	"github.com/gaarutyunov/osv-exporter/osv"
)

type severity struct {
	s osv.Severity
}

func Severity(s osv.Severity) Vulnerability {
	return &severity{s}
}

func (s *severity) Filter(ctx context.Context, vulnerability *osv.Vulnerability) (bool, error) {
	return osv.SeverityMap[vulnerability.Severity] < osv.SeverityMap[s.s], nil
}
