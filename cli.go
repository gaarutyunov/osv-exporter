package main

import (
	"cloud.google.com/go/storage"
	"github.com/gaarutyunov/osv-exporter/exporter"
	"github.com/gaarutyunov/osv-exporter/filter"
	"github.com/gaarutyunov/osv-exporter/osv"
	"github.com/gaarutyunov/osv-exporter/parser"
	"github.com/gaarutyunov/osv-exporter/worker"
	"github.com/google/go-github/v63/github"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/api/option"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

var cmd = &cobra.Command{
	Use:   "osv",
	Short: "Export OSV Database",
}

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export OSV Database",
	RunE:  runExport,
}

func init() {
	pFlags := exportCmd.PersistentFlags()

	pFlags.StringP("bucket", "b", bucket, "Google Cloud Storage bucket name")
	pFlags.IntP("concurrency", "c", limit, "Parsing concurrency")
	pFlags.BoolP("fail", "f", false, "Fail on error")
	pFlags.StringP("out", "o", ".", "Output directory")
	pFlags.StringSliceP("prefix", "p", []string{""}, "Object search prefix")
	pFlags.StringSliceP("extension", "e", []string{}, "Change file extensions filter")
	pFlags.StringP("logging", "l", "/tmp/osv-exporter/export.log", "Log output")
	pFlags.StringP("severity", "s", string(osv.Low), "Vulnerability minimum severity")
	pFlags.StringP("exporter", "x", "meta", "Name of the exporter")

	cmd.AddCommand(exportCmd)
}

func runExport(cmd *cobra.Command, args []string) error {
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

	exporterName, err := pFlags.GetString("exporter")
	if err != nil {
		return err
	}

	gh := github.NewClient(&http.Client{Timeout: time.Second * 100}).WithAuthToken(os.Getenv("GITHUB_TOKEN"))

	gs, err := storage.NewClient(ctx, option.WithoutAuthentication())
	if err != nil {
		return err
	}

	exp, err := exporter.Get(exporterName)
	if err != nil {
		return err
	}

	w := worker.NewWorker(
		ctx,
		gs.Bucket(bucket),
		parser.NewParser(
			gh,
			out,
			parser.WithFilters(filter.Extension(extensions...)),
			parser.WithBurst(concurrency),
			parser.WithExporter(exp),
		),
		worker.WithLimit(concurrency),
		worker.WithFailOnError(failOnError),
		worker.WithFilters(
			filter.Severity(osv.Severity(severity)),
			filter.Fixed(),
		),
	)

	defer w.Close()

	for _, p := range prefix {
		go w.Search(p)
	}

	err = w.Wait()
	if err != nil {
		return err
	}

	return nil
}
