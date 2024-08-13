package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/bluekeyes/go-gitdiff/gitdiff"
	"github.com/google/go-github/v63/github"
	"io"
	"path/filepath"
	"strings"
)

type (
	RepositoryFile interface {
		io.Reader
		io.ReaderAt
	}

	Repository interface {
		ExportChanges(ctx context.Context, vulnerability *Vulnerability, outDir string, file RepositoryFile, changes *gitdiff.File) error
		GetCommitChanges(ctx context.Context, sha string, rawType github.RawType) (Changes, error)
		GetPreviousCommit(ctx context.Context, sha string) (*github.RepositoryCommit, error)
		DownloadFileContents(ctx context.Context, sha, path string) (RepositoryFile, error)
	}

	repository struct {
		*github.RepositoriesService
		org, repo string
	}

	Meta struct {
		Vulnerability

		BadLines  []int64 `json:"bad_lines"`
		GoodLines []int64 `json:"good_lines"`
	}
)

func newRepository(repositoriesService *github.RepositoriesService, org string, repo string) Repository {
	return &repository{RepositoriesService: repositoriesService, org: org, repo: repo}
}

func (r *repository) ExportChanges(ctx context.Context, vulnerability *Vulnerability, outDir string, reader RepositoryFile, changes *gitdiff.File) error {
	err := Open(filepath.Join(outDir, "meta.json"), func(file io.Writer) error {
		v := *vulnerability
		v.References = nil
		meta := Meta{Vulnerability: v}

		for _, fragment := range changes.TextFragments {
			deleteOffset, addOffset := int64(0), int64(0)
			for _, line := range fragment.Lines {
				switch line.Op {
				case gitdiff.OpDelete:
					meta.BadLines = append(meta.BadLines, fragment.OldPosition+deleteOffset)
					deleteOffset += 1
				case gitdiff.OpAdd:
					meta.GoodLines = append(meta.GoodLines, fragment.NewPosition+addOffset)
					addOffset += 1
				default:
					deleteOffset += 1
					addOffset += 1
				}
			}
		}

		metaBytes, err := json.Marshal(meta)
		if err != nil {
			return err
		}
		_, err = file.Write(metaBytes)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	err = Open(filepath.Join(outDir, "old"+filepath.Ext(changes.OldName)), func(file io.Writer) error {
		_, err = io.Copy(file, reader)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	err = Open(filepath.Join(outDir, "new"+filepath.Ext(changes.NewName)), func(file io.Writer) error {
		err = gitdiff.Apply(file, reader, changes)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
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

func (r *repository) DownloadFileContents(ctx context.Context, sha, path string) (RepositoryFile, error) {
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

	return bytes.NewReader(contents), nil
}
