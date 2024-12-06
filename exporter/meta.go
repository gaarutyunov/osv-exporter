package exporter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bluekeyes/go-gitdiff/gitdiff"
	"github.com/gaarutyunov/osv-exporter/osv"
	"github.com/gaarutyunov/osv-exporter/vcs"
	"io"
	"net/url"
	"os"
	"path/filepath"
)

type (
	meta struct {
		metaFileName, oldFileName, newFileName string
	}

	MetaContent struct {
		osv.Vulnerability

		BadLines  []int64 `json:"bad_lines"`
		GoodLines []int64 `json:"good_lines"`
	}
)

// Meta exports a file in a subfolder {root}/{org}.{repo}/{sha}/{escaped_path} in three files: meta, old code version and new version files
func Meta() File {
	return &meta{
		defaultMetaFileName,
		defaultOldFileName,
		defaultNewFileName,
	}
}

const (
	defaultMetaFileName = "meta.json"
	defaultOldFileName  = "old"
	defaultNewFileName  = "new"
)

func mkdirAll(name string) error {
	err := os.MkdirAll(name, os.ModePerm)
	if !errors.Is(err, os.ErrExist) && err != nil {
		return err
	}

	return nil
}

func MetaExporterPath(outDir, org, repo, commit, name string) string {
	return filepath.Join(
		outDir,
		fmt.Sprintf("%s.%s", org, repo),
		commit,
		url.QueryEscape(name),
	)
}

func (m *meta) Export(ctx context.Context, vulnerability *osv.Vulnerability, outDir string, reader vcs.File, changes *gitdiff.File) error {
	outDir = MetaExporterPath(
		outDir,
		reader.GetOrganization(),
		reader.GetRepository(),
		reader.GetSHA(),
		changes.NewName,
	)

	err := mkdirAll(outDir)
	if err != nil {
		return err
	}

	err = writeTo(filepath.Join(outDir, m.metaFileName), func(file io.Writer) error {
		v := *vulnerability
		v.References = nil
		metaContent := MetaContent{Vulnerability: v}

		for _, fragment := range changes.TextFragments {
			deleteOffset, addOffset := int64(0), int64(0)
			for _, line := range fragment.Lines {
				switch line.Op {
				case gitdiff.OpDelete:
					metaContent.BadLines = append(metaContent.BadLines, fragment.OldPosition+deleteOffset)
					deleteOffset += 1
				case gitdiff.OpAdd:
					metaContent.GoodLines = append(metaContent.GoodLines, fragment.NewPosition+addOffset)
					addOffset += 1
				default:
					deleteOffset += 1
					addOffset += 1
				}
			}
		}

		metaBytes, err := json.Marshal(metaContent)
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

	err = writeTo(filepath.Join(outDir, m.oldFileName+filepath.Ext(changes.OldName)), func(file io.Writer) error {
		_, err = io.Copy(file, reader)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	err = writeTo(filepath.Join(outDir, m.newFileName+filepath.Ext(changes.NewName)), func(file io.Writer) error {
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

func writeTo(path string, callback func(file io.Writer) error) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return err
	}

	if cErr := callback(file); cErr != nil {
		err := file.Close()
		if err != nil {
			return err
		}
		err = os.Remove(path)
		if err != nil {
			return err
		}

		return cErr
	}

	err = file.Close()
	if err != nil {
		return err
	}

	return nil
}
