package main

import (
	"context"
	"fmt"
	"github.com/bluekeyes/go-gitdiff/gitdiff"
	"github.com/google/go-github/v63/github"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type (
	FileFilter interface {
		Filter(ctx context.Context, file *gitdiff.File) (bool, error)
	}

	Parser struct {
		*github.Client
		out string

		filters []FileFilter
	}
)

var so sync.Once
var mx sync.Mutex
var rl = rate.NewLimiter(defaultLimitsPerHour/secondsPerHour, 1)

func NewParser(client *github.Client, out string, opts ...func(parser *Parser)) *Parser {
	parser := &Parser{Client: client, out: out}

	for _, opt := range opts {
		opt(parser)
	}

	return parser
}

func SetBurst(n int) {
	rl.SetBurst(n)
}

func WithFileFilters(f ...FileFilter) func(parser *Parser) {
	return func(parser *Parser) {
		parser.filters = append(parser.filters, f...)
	}
}

func WithBurst(n int) func(parser *Parser) {
	return func(parser *Parser) {
		SetBurst(n)
	}
}

func UpdateRateLimit(ctx context.Context, client *github.Client, lock bool) error {
	if lock {
		mx.Lock()
		defer mx.Unlock()
	}

	rateLimits, _, err := client.RateLimit.Get(ctx)
	if err != nil {
		return err
	}

	rl.SetLimitAt(
		rateLimits.Core.Reset.Time.Add(-time.Hour),
		rate.Limit(rateLimits.Core.Limit),
	)

	return nil
}

func (p *Parser) Parse(ctx context.Context, vulnerability *Vulnerability) error {
	so.Do(func() {
		err := UpdateRateLimit(ctx, p.Client, false)
		if err != nil {
			log.Errorf("error getting rate limits: %v", err)
			return
		}
	})

	for _, reference := range vulnerability.References {
		match, ok := regexpSearch(commitRegExp, reference.URL.String())
		if !ok {
			continue
		}
		org, repo, commit := match["org"], match["repo"], match["commit"]

		repository := newRepository(p.Repositories, org, repo)

		changes, err := repository.GetCommitChanges(ctx, commit, github.Diff)
		if err != nil {
			return err
		}

		prevCommit, err := repository.GetPreviousCommit(ctx, commit)
		if err != nil {
			return err
		}

		outDir := filepath.Join(p.out, fmt.Sprintf("%s.%s", org, repo), commit)

		err = MkdirAll(outDir)
		if err != nil {
			return err
		}

	ChangesLoop:
		for _, change := range changes.GetFiles() {
			for _, filter := range p.filters {
				if ok, err := filter.Filter(ctx, change); err != nil {
					return err
				} else if ok {
					continue ChangesLoop
				}
			}

			var oldFile RepositoryFile

			if change.IsNew {
				oldFile = strings.NewReader("")
			} else {
				oldFile, err = repository.DownloadFileContents(ctx, prevCommit.GetSHA(), change.OldName)
				if err != nil {
					return err
				}
			}

			outDir := filepath.Join(outDir, url.QueryEscape(change.NewName))

			err = MkdirAll(outDir)
			if err != nil {
				return err
			}

			err = repository.ExportChanges(ctx, vulnerability, outDir, oldFile, change)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
