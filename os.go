package main

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func Open(path string, callback func(file io.Writer) error) error {
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

func MkdirAll(name string) error {
	err := os.MkdirAll(name, os.ModePerm)
	if !errors.Is(err, os.ErrExist) && err != nil {
		return err
	}

	return nil
}

func MustExpandUser(path string) string {
	if !strings.HasPrefix(path, "~") {
		return path
	}

	dir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Failed to get home dir: %s", err)
	}

	if path == "~" {
		return dir
	} else if strings.HasPrefix(path, "~/") {
		return filepath.Join(dir, path[2:])
	}

	panic("unreachable")
}
