package parser

import (
	"context"
	"github.com/gaarutyunov/osv-exporter/exporter"
	"github.com/gaarutyunov/osv-exporter/filter"
	"github.com/gaarutyunov/osv-exporter/osv"
	"github.com/gaarutyunov/osv-exporter/re"
	"github.com/gaarutyunov/osv-exporter/vcs"
	"github.com/google/go-github/v63/github"
	"github.com/sirupsen/logrus"
	"strings"
	"sync"
)

type Parser struct {
	*github.Client
	out string

	filters  []filter.File
	exporter exporter.File
}

var so sync.Once

func NewParser(client *github.Client, out string, opts ...func(parser *Parser)) *Parser {
	parser := &Parser{
		Client:   client,
		out:      out,
		exporter: exporter.Meta(),
	}

	for _, opt := range opts {
		opt(parser)
	}

	return parser
}

func (p *Parser) Parse(ctx context.Context, vulnerability *osv.Vulnerability) error {
	so.Do(func() {
		err := vcs.UpdateRateLimit(ctx, p.Client, false)
		if err != nil {
			logrus.Errorf("error getting rate limits: %v", err)
			return
		}
	})

	for _, reference := range vulnerability.References {
		match, ok := re.Search(re.GithubCommit, reference.URL.String())
		if !ok {
			continue
		}
		commit := match["commit"]

		repository := vcs.NewRepository(p.Repositories, match["org"], match["repo"])

		changes, err := repository.GetCommitChanges(ctx, commit, github.Diff)
		if err != nil {
			return err
		}

		prevCommit, err := repository.GetPreviousCommit(ctx, commit)
		if err != nil {
			return err
		}

	ChangesLoop:
		for _, change := range changes.GetFiles() {
			for _, fileFilter := range p.filters {
				if filtered, err := fileFilter.Filter(ctx, change); err != nil {
					return err
				} else if filtered {
					continue ChangesLoop
				}
			}

			var oldFile vcs.File

			if change.IsNew {
				oldFile = vcs.NewFile(
					strings.NewReader(""),
					repository.GetOrganization(),
					repository.GetRepository(),
					commit,
				)
			} else {
				oldFile, err = repository.DownloadFileContents(ctx, prevCommit.GetSHA(), change.OldName)
				if err != nil {
					return err
				}
			}

			err = p.exporter.Export(ctx, vulnerability, p.out, oldFile, change)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
