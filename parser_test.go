package main

import (
	"context"
	"encoding/json"
	"github.com/google/go-github/v63/github"
	"github.com/stretchr/testify/assert"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestParserAll(t *testing.T) {
	client := github.NewClient(nil).WithAuthToken(os.Getenv("GITHUB_TOKEN"))

	ctx := context.Background()

	outDir := t.TempDir()

	parser := NewParser(client, outDir, WithFileFilters(NewExtensionFilter(".py")))

	const vulnURL = "https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2024/07/GHSA-cgcg-p68q-3w7v/GHSA-cgcg-p68q-3w7v.json"

	vuln, err := getVulnerability(vulnURL)
	if err != nil {
		t.Fatalf("Error getting vulnerability: %v", err)
	}

	err = parser.Parse(ctx, vuln)
	if err != nil {
		t.Fatalf("Error parsing vulnerability: %v", err)
	}

	filePath := url.QueryEscape("libs/experimental/langchain_experimental/sql/vector_sql.py")
	const sha = "7b13292e3544b2f5f2bfb8a27a062ea2b0c34561"

	parsedDir := filepath.Join(outDir, "langchain-ai.langchain", sha, filePath)

	assert.DirExists(t, parsedDir)
	assert.FileExists(t, filepath.Join(parsedDir, "meta.json"))
	assert.FileExists(t, filepath.Join(parsedDir, "old.py"))
	assert.FileExists(t, filepath.Join(parsedDir, "new.py"))

	metaRaw, err := os.ReadFile(filepath.Join(parsedDir, "meta.json"))
	if err != nil {
		t.Fatalf("os.ReadFile(%q): %v", filePath, err)
	}

	var meta Meta

	err = json.Unmarshal(metaRaw, &meta)
	if err != nil {
		t.Fatalf("json.Unmarshal(%q): %v", filePath, err)
	}

	assert.Equal(t, []int64{11, 79, 80, 81, 82, 83, 84, 85, 90, 91, 92, 93, 94, 95}, meta.BadLines)
	assert.Equal(t, []int64{11, 83}, meta.GoodLines)
}
