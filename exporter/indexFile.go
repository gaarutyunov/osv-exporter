package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/bluekeyes/go-gitdiff/gitdiff"
	"github.com/gaarutyunov/osv-exporter/osv"
	"github.com/gaarutyunov/osv-exporter/vcs"
	"github.com/google/uuid"
)

const (
	indexFileName = "index.jsonl"
)

type (
	indexFile struct {
		newName, indexFileName string
	}

	IndexFileContent struct {
		OldFilepath string `jsonl:"filepath"`
		osv.DatabaseSpecific
		Diff      string  `jsonl:"diff"`
		BadLines  []int64 `jsonl:"bad_lines"`
		GoodLines []int64 `jsonl:"good_lines"`
	}
)

// Record exports a file in a subfolder {root}/{org}.{repo}/{sha}/{programming lang}/{escaped_path} in two files: record(indexed file), old code version
func IndexFile() File {
	return &indexFile{
		uuid.NewString(), indexFileName}
}

func IndexFileT(str string) File {
	return &indexFile{str, indexFileName}
}

func IndexFileExporterPath(outDir, extension string) string {
	return filepath.Join(
		outDir,
		extension,
	)
}

func (r *indexFile) Export(ctx context.Context, vulnerability *osv.Vulnerability, outDir string, reader vcs.File, changes *gitdiff.File) error {
	indexfilepath := outDir
	//Record exports a file in a subfolder {root}/{org}.{repo}/{sha}/{programming lang}/{escaped_path} in two files: record(indexed file), old code version

	outDir = IndexFileExporterPath(
		outDir,
		filepath.Ext(changes.OldName),
	)

	err := mkdirAll(outDir)
	if err != nil {
		return err
	}
	//Creating copies of files with vulnerabilities with unique names
	err = writeToIndex(filepath.Join(outDir, r.newName+filepath.Ext(changes.OldName)), func(file io.Writer) error {
		_, err = io.Copy(file, reader)
		if err != nil {
			return err
		}
		return nil
	})
	//Creating one indexed file with every record of vulnerable file
	err = writeToIndex(filepath.Join(indexfilepath, r.indexFileName), func(file io.Writer) error {
		v := *vulnerability
		//v.References = nil
		//ch := *changes
		recContent := IndexFileContent{DatabaseSpecific: v.DatabaseSpecific, OldFilepath: changes.OldName}
		for _, fragment := range changes.TextFragments {
			deleteOffset, addOffset := int64(0), int64(0)
			recContent.Diff = recContent.Diff + fragment.Header()
			for _, line := range fragment.Lines {
				switch line.Op {
				case gitdiff.OpDelete:
					recContent.BadLines = append(recContent.BadLines, fragment.OldPosition+deleteOffset)
					deleteOffset += 1
				case gitdiff.OpAdd:
					recContent.GoodLines = append(recContent.GoodLines, fragment.NewPosition+addOffset)
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
		var recLine bytes.Buffer
		err = json.Compact(&recLine, recBytes)
		if err != nil {
			return err
		}
		_, err = file.Write(recLine.Bytes())
		if err != nil {
			return err
		}
		return nil
	})

	return nil
}
func writeToIndex(path string, callback func(file io.Writer) error) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, os.ModePerm)
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
