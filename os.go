package main

import (
	log "github.com/sirupsen/logrus"
	"os"
	"path/filepath"
	"strings"
)

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
