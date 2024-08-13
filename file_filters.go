package main

import (
	"context"
	"github.com/bluekeyes/go-gitdiff/gitdiff"
	"path/filepath"
)

type ExtensionFilter struct {
	extensions []string
}

func NewExtensionFilter(extensions ...string) *ExtensionFilter {
	return &ExtensionFilter{extensions: extensions}
}

func (f *ExtensionFilter) Filter(ctx context.Context, file *gitdiff.File) (bool, error) {
	for _, extension := range f.extensions {
		if extension == filepath.Ext(file.NewName) {
			return false, nil
		}
	}

	return true, nil
}
