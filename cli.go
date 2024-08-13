package main

import (
	"cloud.google.com/go/storage"
	"github.com/google/go-github/v63/github"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/api/option"
	"os"
	"path/filepath"
)

var cmd = &cobra.Command{
	Use:   "osv",
	Short: "Export OSV Database",
	RunE:  run,
}

func init() {
	pFlags := cmd.PersistentFlags()

	pFlags.StringP("bucket", "b", bucket, "Google Cloud Storage bucket name")
	pFlags.IntP("concurrency", "c", limit, "Parsing concurrency")
	pFlags.BoolP("fail", "f", false, "Fail on error")
	pFlags.StringP("out", "o", ".", "Output directory")
	pFlags.StringSliceP("prefix", "p", []string{""}, "Object search prefix")
	pFlags.StringSliceP("extension", "e", []string{}, "Change file extensions filter")
	pFlags.StringP("logging", "l", "/tmp/osv-exporter/export.log", "Log output")
	pFlags.StringP("severity", "s", string(Low), "Vulnerability minimum severity")
}

func run(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	pFlags := cmd.PersistentFlags()

	logging, err := pFlags.GetString("logging")
	if err != nil {
		return err
	}

	logging = MustExpandUser(logging)

	err = os.MkdirAll(filepath.Dir(logging), os.ModePerm)
	if err != nil {
		return err
	}

	logOutput, err := os.OpenFile(logging, os.O_CREATE|os.O_APPEND|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return err
	}

	log.SetOutput(logOutput)

	out, err := pFlags.GetString("out")
	if err != nil {
		return err
	}

	out = MustExpandUser(out)

	severity, err := pFlags.GetString("severity")
	if err != nil {
		return err
	}

	bucket, err := pFlags.GetString("bucket")
	if err != nil {
		return err
	}

	concurrency, err := pFlags.GetInt("concurrency")
	if err != nil {
		return err
	}

	failOnError, err := pFlags.GetBool("fail")
	if err != nil {
		return err
	}

	extensions, err := pFlags.GetStringSlice("extension")
	if err != nil {
		return err
	}

	prefix, err := pFlags.GetStringSlice("prefix")
	if err != nil {
		return err
	}

	gh := github.NewClient(nil).WithAuthToken(os.Getenv("GITHUB_TOKEN"))

	gs, err := storage.NewClient(ctx, option.WithoutAuthentication())
	if err != nil {
		return err
	}

	worker := NewWorker(
		ctx,
		gs.Bucket(bucket),
		NewParser(
			gh,
			out,
			WithFileFilters(NewExtensionFilter(extensions...)),
			WithBurst(concurrency),
		),
		WithLimit(concurrency),
		WithFailOnError(failOnError),
		WithVulnerabilityFilters(NewSeverityFilter(Severity(severity)), NewFixFilter()),
	)

	defer worker.Close()

	for _, prefix := range prefix {
		go worker.Search(prefix)
	}

	err = worker.Wait()
	if err != nil {
		return err
	}

	return nil
}
