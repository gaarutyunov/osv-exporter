package vcs

import "io"

type (
	Reader interface {
		io.Reader
		io.ReaderAt
	}

	File interface {
		Reader

		GetOrganization() string
		GetRepository() string
		GetSHA() string
	}

	repositoryFile struct {
		Reader
		org, repo, commit string
	}
)

func NewFile(reader Reader, org, repo, commit string) File {
	return &repositoryFile{Reader: reader, org: org, repo: repo, commit: commit}
}

func (r *repositoryFile) GetOrganization() string {
	return r.org
}

func (r *repositoryFile) GetRepository() string {
	return r.repo
}

func (r *repositoryFile) GetSHA() string {
	return r.commit
}
