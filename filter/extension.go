package filter

import (
	"context"
	"github.com/bluekeyes/go-gitdiff/gitdiff"
	"path/filepath"
)

type extension struct {
	extensions []string
}

func Extension(extensions ...string) File {
	return &extension{extensions: extensions}
}

func (f *extension) Filter(ctx context.Context, file *gitdiff.File) (bool, error) {
	for _, ext := range f.extensions {
		if ext == filepath.Ext(file.NewName) {
			return false, nil
		}
	}

	return true, nil
}
