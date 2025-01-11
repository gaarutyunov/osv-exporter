package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"

	"github.com/bluekeyes/go-gitdiff/gitdiff"
	"github.com/gaarutyunov/osv-exporter/osv"
	"github.com/gaarutyunov/osv-exporter/vcs"
	"github.com/google/uuid"
)

type (
	record struct {
		defaultOldFileName, indexedfilename string
	}

	RecordContent struct {
		oldFilepath string
		osv.Vulnerability
		changes   *gitdiff.File
		severity  osv.Severity
		badLines  []int64
		goodLines []int64
	}
)

// Record exports a file in a subfolder {root}/{org}.{repo}/{sha}/{programming lang}/{escaped_path} in two files: record(indexed file), old code version
func Record() File {
	return &record{
		defaultOldFileName, uuid.NewString()}
}

func RecordExporterPath(outDir, org, repo, commit, extension, name string) string {
	return filepath.Join(
		outDir,
		fmt.Sprintf("%s.%s", org, repo),
		commit,
		extension,
		url.QueryEscape(name),
	)
}

func (r *record) Export(ctx context.Context, vulnerability *osv.Vulnerability, outDir string, reader vcs.File, changes *gitdiff.File) error {

	//Record exports a file in a subfolder {root}/{org}.{repo}/{sha}/{programming lang}/{escaped_path} in two files: record(indexed file), old code version
	outDir = RecordExporterPath(
		outDir,
		reader.GetOrganization(),
		reader.GetRepository(),
		reader.GetSHA(),
		filepath.Ext(changes.OldName),
		uuid.NewString(),
	)

	err := mkdirAll(outDir)
	if err != nil {
		return err
	}

	err = writeTo(filepath.Join(outDir, r.indexedfilename+".json"), func(file io.Writer) error {
		v := *vulnerability
		v.References = nil
		recContent := RecordContent{Vulnerability: v, changes: changes, severity: v.Severity, oldFilepath: filepath.Base(changes.OldName)}

		for _, fragment := range changes.TextFragments {
			deleteOffset, addOffset := int64(0), int64(0)
			for _, line := range fragment.Lines {
				switch line.Op {
				case gitdiff.OpDelete:
					recContent.badLines = append(recContent.badLines, fragment.OldPosition+deleteOffset)
					deleteOffset += 1
				case gitdiff.OpAdd:
					recContent.goodLines = append(recContent.goodLines, fragment.NewPosition+addOffset)
					addOffset += 1
				default:
					deleteOffset += 1
					addOffset += 1
				}
			}
		}

		recBytes, err := json.Marshal(recContent)
		if err != nil {
			return err
		}
		var recLine *bytes.Buffer
		err = json.Compact(recLine, recBytes)
		if err != nil {
			return err
		}
		_, err = file.Write(recLine.Bytes())
		if err != nil {
			return err
		}
		return nil
	})

	err = writeTo(filepath.Join(outDir, r.defaultOldFileName+filepath.Ext(changes.OldName)), func(file io.Writer) error {
		_, err = io.Copy(file, reader)
		if err != nil {
			return err
		}
		return nil
	})

	return nil
}
