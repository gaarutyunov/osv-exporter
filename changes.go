package main

import "github.com/bluekeyes/go-gitdiff/gitdiff"

type (
	Changes interface {
		GetFiles() []*gitdiff.File
		GetPreamble() string
	}

	changes struct {
		files    []*gitdiff.File
		preamble string
	}
)

func newChanges(files []*gitdiff.File, preamble string) Changes {
	return &changes{files: files, preamble: preamble}
}

func (c *changes) GetFiles() []*gitdiff.File {
	return c.files
}

func (c *changes) GetPreamble() string {
	return c.preamble
}
