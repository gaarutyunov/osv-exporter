package main

import (
	"bufio"
	"cloud.google.com/go/storage"
	"encoding/json"
	"fmt"
	"github.com/gaarutyunov/ovs-exporter/joern"
	"github.com/google/go-github/v63/github"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/option"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import OSV Database into joern",
	RunE:  runImport,
}

const joernServer = "localhost:8080"

func init() {
	pFlags := exportCmd.PersistentFlags()

	pFlags.StringP("bucket", "b", bucket, "Google Cloud Storage bucket name")
	pFlags.IntP("concurrency", "c", limit, "Parsing concurrency")
	pFlags.BoolP("fail", "f", false, "Fail on error")
	pFlags.StringP("out", "o", ".", "Output directory")
	pFlags.StringSliceP("prefix", "p", []string{""}, "Object search prefix")
	pFlags.StringSliceP("extension", "e", []string{}, "Change file extensions filter")
	pFlags.StringP("logging", "l", "/tmp/osv-exporter/export.log", "Log output")
	pFlags.StringP("severity", "s", string(Low), "Vulnerability minimum severity")

	pFlags = importCmd.PersistentFlags()
	pFlags.StringP("in", "i", ".", "Input directory")
	pFlags.IntP("concurrency", "c", limit, "Import concurrency")
	pFlags.StringP("server", "s", joernServer, "Joern server host")
	pFlags.StringP("logging", "l", "/tmp/osv-exporter/import.log", "Log output")
	pFlags.StringP("user", "u", "", "Joern server user")
	pFlags.BoolP("insecure", "k", false, "Joern server without authentication")

	cmd.AddCommand(exportCmd, importCmd)
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

	gh := github.NewClient(&http.Client{Timeout: time.Second * 100}).WithAuthToken(os.Getenv("GITHUB_TOKEN"))

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

var getPassword = func() (string, error) {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return scanner.Text(), nil
}

func runImport(cmd *cobra.Command, args []string) error {
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

	in, err := pFlags.GetString("in")
	if err != nil {
		return err
	}

	in = MustExpandUser(in)

	concurrency, err := pFlags.GetInt("concurrency")
	if err != nil {
		return err
	}

	server, err := pFlags.GetString("server")
	if err != nil {
		return err
	}

	insecure, err := pFlags.GetBool("insecure")
	if err != nil {
		return err
	}

	var user, pass string

	if !insecure {
		user, err = pFlags.GetString("user")
		if err != nil {
			return err
		}

		fmt.Println("Enter joern server password below:")

		pass, err = getPassword()
		if err != nil {
			return err
		}
	}

	client := joern.NewClient(server, user, pass)

	matches, err := filepath.Glob(filepath.Join(in, "*/*/*/meta.json"))
	if err != nil {
		return err
	}

	var wg errgroup.Group
	wg.SetLimit(concurrency)

	var counter atomic.Uint32
	var doneCounter atomic.Uint32

	for _, match := range matches {
		match := match

		wg.Go(func() error {
			var m Meta

			f, err := os.Open(match)
			if err != nil {
				return err
			}

			defer f.Close()

			err = json.NewDecoder(f).Decode(&m)
			if err != nil {
				return err
			}

			if len(m.BadLines) == 0 {
				return nil
			}

			dir := filepath.Dir(match)
			rel, err := filepath.Rel(in, dir)
			if err != nil {
				return err
			}
			projectName := strings.ReplaceAll(rel, string(filepath.Separator), ".")

			err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				if strings.HasPrefix(info.Name(), "old") {
					_, err = client.Send(ctx, fmt.Sprintf("importCode(inputPath=\"%s\", projectName=\"%s\")", path, projectName))
					if err != nil {
						return err
					}
					counter.Add(1)
				}

				return nil
			})
			if err != nil {
				return err
			}

			return nil
		})
	}

	err = client.Open(ctx)
	if err != nil {
		return err
	}

	m, err := client.Receive(ctx)
	if err != nil {
		return err
	}

	if m != joern.Connected {
		return fmt.Errorf("could not connect to %s", server)
	}

	doneCh := make(chan struct{})
	importedCh := make(chan uuid.UUID)

	defer close(importedCh)

	go func() {
		for id := range importedCh {
			result, err := client.Result(ctx, id)
			if err != nil {
				log.Errorf("could not retrieve result for %s: %v", id, err)
				return
			}
			if !result.Success {
				log.Errorf("failed importing code for %s: \n%s", id, result.Stderr)
			}
			doneCounter.Add(1)
			if doneCounter.CompareAndSwap(counter.Load(), 0) {
				doneCh <- struct{}{}
				close(doneCh)
				break
			}
		}
	}()

	go func() {
		for {
			select {
			case <-doneCh:
				return
			default:
			}
			m, err := client.Receive(ctx)
			if err != nil {
				log.Errorf("could not recieve: %v", err)
				return
			}
			select {
			case <-doneCh:
				return
			default:
			}
			id, err := uuid.Parse(m)
			if err != nil {
				log.Errorf("could not parse message %s: %v", m, err)
				return
			}
			importedCh <- id
		}
	}()

	err = wg.Wait()
	if err != nil {
		return err
	}

	<-doneCh

	return nil
}
