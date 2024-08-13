package main

import (
	"bufio"
	"cloud.google.com/go/storage"
	"context"
	"github.com/google/go-github/v63/github"
	"google.golang.org/api/option"
	"os"
	"strings"
	"testing"
)

const vulnerabilities = `GHSA-4hq2-rpgc-r8r7
GHSA-jwhx-xcg6-8xhj
GHSA-9x4q-3gxw-849f
GHSA-5jp3-wp5v-5363
GHSA-9m5j-4xx9-44j9
GHSA-795c-9xpc-xw6g
GHSA-jh75-99hh-qvx9
GHSA-pv4p-cwwg-4rph
GHSA-r836-hh6v-rg5g
PYSEC-2024-67
PYSEC-2024-68
PYSEC-2024-69
PYSEC-2024-70
GHSA-pcwp-26pw-j98w
GHSA-f729-58x4-gqgf
GHSA-3g4c-hjhr-73rj
GHSA-v7gr-mqpj-wwh3
GHSA-8pv9-qh96-9hc6
GHSA-h856-ffvv-xvr4
GHSA-w7c4-5w4f-jm3g
GHSA-4hvc-qwr2-f8rv
GHSA-f984-3wx8-grp9
GHSA-p78h-m8pv-g9gm
GHSA-2w4p-2hf7-gh8x
GHSA-whr2-9x5f-5c79
GHSA-frvj-cfq4-3228
GHSA-9w8w-34vr-65j2
GHSA-j6vx-r77h-44wc
GHSA-qff2-8qw7-hcvw
GHSA-v352-rg37-5q5m
GHSA-5hcj-rwm6-xmw4
GHSA-5v8f-xx9m-wj44
CVE-2024-3651
CVE-2024-5171
CVE-2024-32760
CVE-2024-32002
CVE-2024-27316
CVE-2024-3094
CVE-2024-28960
CVE-2024-28085
CVE-2024-2004
GHSA-2rwj-7xq8-4gx4
GHSA-f83w-wqhc-cfp4
MAL-2024-7897
MAL-2024-7904
MAL-2024-7905
GHSA-2jch-qc96-9f5g
GHSA-858c-qxvx-rg9v
GHSA-fccx-2pwj-hrq7
GHSA-wxm4-9f8p-gggv
GHSA-vf6r-87q4-2vjf
GHSA-rcvg-rgf7-pppv
MAL-2024-7895
MAL-2024-7893
GHSA-ffxg-5f8m-h72j
GHSA-5cf7-cxrf-mq73
GHSA-mpg4-rc92-vx8v
GHSA-28mc-g557-92m7	
GHSA-3jcg-vx7f-j6qf`

func TestWorkerAll(t *testing.T) {
	ctx := context.Background()

	storageClient, err := storage.NewClient(ctx, option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("Failed to create storageClient: %v", err)
	}

	bucket := storageClient.Bucket(bucket)

	githubCilent := github.NewClient(nil).WithAuthToken(os.Getenv("GITHUB_TOKEN"))

	outDir := t.TempDir()

	worker := NewWorker(
		ctx,
		bucket,
		NewParser(
			githubCilent,
			outDir,
			WithFileFilters(NewExtensionFilter(
				".py",
				".java",
				".c",
				".h",
				".cpp",
				".js",
				".jsx",
				".ts",
				".tsx",
				".kt",
				".kts",
			)),
		),
		WithVulnerabilityFilters(NewSeverityFilter(Low), NewFixFilter()),
		WithLimit(20),
	)

	roots := []string{"PyPI", "Alpine", "npm", "Maven"}

	for _, root := range roots {
		scanner := bufio.NewScanner(strings.NewReader(vulnerabilities))

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			go worker.Search(root + "/" + line)
		}
	}

	err = worker.Wait()
	if err != nil {
		t.Fatalf("Failed to run worker: %v", err)
	}
}
