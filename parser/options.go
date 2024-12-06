package parser

import (
	"github.com/gaarutyunov/osv-exporter/exporter"
	"github.com/gaarutyunov/osv-exporter/filter"
	"github.com/gaarutyunov/osv-exporter/vcs"
)

func WithFilters(f ...filter.File) func(parser *Parser) {
	return func(parser *Parser) {
		parser.filters = append(parser.filters, f...)
	}
}

func WithBurst(n int) func(parser *Parser) {
	return func(parser *Parser) {
		vcs.SetBurst(n)
	}
}

func WithExporter(e exporter.File) func(parser *Parser) {
	return func(parser *Parser) {
		parser.exporter = e
	}
}
