package vcs

import (
	"bytes"
	"context"
	"fmt"
	"github.com/bluekeyes/go-gitdiff/gitdiff"
	"github.com/google/go-github/v63/github"
	"io"
	"strings"
)

type (
	Repository interface {
		GetOrganization() string
		GetRepository() string
		GetCommitChanges(ctx context.Context, sha string, rawType github.RawType) (Changes, error)
		GetPreviousCommit(ctx context.Context, sha string) (*github.RepositoryCommit, error)
		DownloadFileContents(ctx context.Context, sha, path string) (File, error)
	}

	repository struct {
		*github.RepositoriesService
		org, repo string
	}
)

func (r *repository) GetOrganization() string {
	return r.org
}

func (r *repository) GetRepository() string {
	return r.repo
}

func NewRepository(repositoriesService *github.RepositoriesService, org, repo string) Repository {
	return &repository{RepositoriesService: repositoriesService, org: org, repo: repo}
}

func (r *repository) GetCommitChanges(ctx context.Context, sha string, rawType github.RawType) (Changes, error) {
	err := rl.Wait(ctx)
	if err != nil {
		return nil, err
	}
	raw, _, err := r.GetCommitRaw(ctx, r.org, r.repo, sha, github.RawOptions{Type: rawType})
	if err != nil {
		return nil, err
	}

	files, _, err := gitdiff.Parse(strings.NewReader(raw))
	if err != nil {
		return nil, err
	}

	return newChanges(files, sha), nil
}

func (r *repository) GetPreviousCommit(ctx context.Context, sha string) (prevCommit *github.RepositoryCommit, err error) {
	err = rl.Wait(ctx)
	if err != nil {
		return nil, err
	}
	commits, _, err := r.ListCommits(ctx, r.org, r.repo, &github.CommitsListOptions{
		SHA: sha,
		ListOptions: github.ListOptions{
			Page:    2,
			PerPage: 1,
		},
	})
	if err != nil {
		return nil, err
	}

	if len(commits) == 0 {
		return nil, fmt.Errorf("%s/%s: no previous commits found for %s", r.org, r.repo, sha)
	}

	prevCommit = commits[0]

	return
}

func (r *repository) DownloadFileContents(ctx context.Context, sha, path string) (File, error) {
	err := rl.Wait(ctx)
	if err != nil {
		return nil, err
	}
	prevReader, _, err := r.DownloadContents(ctx, r.org, r.repo, path, &github.RepositoryContentGetOptions{
		Ref: sha,
	})
	if err != nil {
		return nil, err
	}

	contents, err := io.ReadAll(prevReader)
	if err != nil {
		return nil, err
	}

	return NewFile(bytes.NewReader(contents), r.org, r.repo, sha), nil
}
