package parser

import (
	"context"
	"encoding/json"
	"github.com/gaarutyunov/osv-exporter/exporter"
	"github.com/gaarutyunov/osv-exporter/filter"
	"github.com/gaarutyunov/osv-exporter/osv"
	"github.com/google/go-github/v63/github"
	"github.com/stretchr/testify/assert"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func getVulnerability(url string) (*osv.Vulnerability, error) {
	var vuln osv.Vulnerability

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	err = json.NewDecoder(resp.Body).Decode(&vuln)
	if err != nil {
		return nil, err
	}

	return &vuln, nil
}

func TestParserAll(t *testing.T) {
	client := github.NewClient(nil).WithAuthToken(os.Getenv("GITHUB_TOKEN"))

	ctx := context.Background()

	outDir := t.TempDir()

	parser := NewParser(client, outDir, WithFilters(filter.Extension(".py")))

	const vulnURL = "https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2024/07/GHSA-cgcg-p68q-3w7v/GHSA-cgcg-p68q-3w7v.json"

	vuln, err := getVulnerability(vulnURL)
	if err != nil {
		t.Fatalf("Error getting vulnerability: %v", err)
	}

	err = parser.Parse(ctx, vuln)
	if err != nil {
		t.Fatalf("Error parsing vulnerability: %v", err)
	}

	const sha = "b809c243afb182efc5868ca495074a41e2f7c40c"

	parsedDir := exporter.MetaExporterPath(
		outDir,
		"langchain-ai",
		"langchain",
		sha,
		"libs/experimental/langchain_experimental/sql/vector_sql.py",
	)

	assert.DirExists(t, parsedDir)
	assert.FileExists(t, filepath.Join(parsedDir, "meta.json"))
	assert.FileExists(t, filepath.Join(parsedDir, "old.py"))
	assert.FileExists(t, filepath.Join(parsedDir, "new.py"))

	metaRaw, err := os.ReadFile(filepath.Join(parsedDir, "meta.json"))
	if err != nil {
		t.Fatal(err)
	}

	var meta exporter.MetaContent

	err = json.Unmarshal(metaRaw, &meta)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, []int64{11, 79, 80, 81, 82, 83, 84, 85, 90, 91, 92, 93, 94, 95}, meta.BadLines)
	assert.Equal(t, []int64{11, 83}, meta.GoodLines)
}
