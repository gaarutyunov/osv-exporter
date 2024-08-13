package main

import (
	"cloud.google.com/go/storage"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"google.golang.org/api/iterator"
	"io"
	"sync"
	"sync/atomic"
)

type (
	token struct{}

	VulnerabilityParser interface {
		Parse(ctx context.Context, vulnerability *Vulnerability) error
	}

	VulnerabilityFilter interface {
		Filter(ctx context.Context, vulnerability *Vulnerability) (bool, error)
	}

	PrefixAndName [2]string

	Worker struct {
		*storage.BucketHandle

		defaultParser VulnerabilityParser

		parsers map[string]VulnerabilityParser
		filters []VulnerabilityFilter

		ctx context.Context

		doneCh   chan struct{}
		decodeCh chan *Vulnerability
		nameCh   chan PrefixAndName
		token    chan token

		counter     atomic.Uint32
		doneCounter atomic.Uint32

		err error

		failErr bool

		errOnce sync.Once
	}
)

func NewWorker(ctx context.Context, bucket *storage.BucketHandle, defaultParser VulnerabilityParser, opts ...func(worker *Worker)) *Worker {
	w := &Worker{
		BucketHandle:  bucket,
		defaultParser: defaultParser,
		ctx:           ctx,
		doneCh:        make(chan struct{}),
		decodeCh:      make(chan *Vulnerability),
		nameCh:        make(chan PrefixAndName),
		failErr:       true,
		token:         nil,
	}

	for _, opt := range opts {
		opt(w)
	}

	return w
}

func WithVulnerabilityFilters(filters ...VulnerabilityFilter) func(worker *Worker) {
	return func(worker *Worker) {
		worker.filters = append(worker.filters, filters...)
	}
}

func WithLimit(limit int) func(worker *Worker) {
	return func(w *Worker) {
		w.SetLimit(limit)
	}
}

func WithFailOnError(fail bool) func(worker *Worker) {
	return func(w *Worker) {
		w.SetFailOnError(fail)
	}
}

func (w *Worker) SetFailOnError(b bool) {
	if len(w.token) != 0 {
		panic(fmt.Errorf("worker: modify failErr while %v goroutines in the group are still active", len(w.token)))
	}
	w.failErr = b
}

func (w *Worker) SetLimit(n int) {
	if n <= 0 {
		w.token = nil
		return
	}
	if len(w.token) != 0 {
		panic(fmt.Errorf("worker: modify limit while %v goroutines in the group are still active", len(w.token)))
	}
	w.token = make(chan token, n)
}

func (w *Worker) SetParser(prefix string, parser VulnerabilityParser) {
	w.parsers[prefix] = parser
}

func WithParser(prefix string, parser VulnerabilityParser) func(worker *Worker) {
	return func(worker *Worker) {
		worker.SetParser(prefix, parser)
	}
}

func (w *Worker) Parse(ctx context.Context, v *Vulnerability) error {
	p, ok := w.parsers[v.prefix]
	if !ok {
		return w.defaultParser.Parse(ctx, v)
	}

	return p.Parse(ctx, v)
}

func (w *Worker) setError(err error, critical bool) {
	if !critical && !w.failErr {
		log.Error(err)
		return
	}

	w.errOnce.Do(func() {
		w.err = err
		w.doneCh <- struct{}{}
	})
}

func (w *Worker) Search(prefix string) {
	it := w.Objects(w.ctx, &storage.Query{
		Prefix: prefix,
	})

	for {
		select {
		case <-w.ctx.Done():
			return
		default:
		}
		var attrs *storage.ObjectAttrs
		err := w.wrap(func() (err error) {
			attrs, err = it.Next()

			return err
		})
		if errors.Is(err, iterator.Done) {
			return
		}

		if err != nil {
			w.setError(err, true)
			return
		}

		w.nameCh <- PrefixAndName{prefix, attrs.Name}
	}
}

func (w *Worker) wrap(f func() error) error {
	w.acquire()
	defer w.release()

	return f()
}

func (w *Worker) acquire() {
	if w.token == nil {
		return
	}

	w.token <- struct{}{}
}

func (w *Worker) release() {
	if w.token == nil {
		return
	}

	<-w.token
}

func (w *Worker) Wait() error {
	w.counter.Store(0)
	w.doneCounter.Store(0)

	go func() {
		for v := range w.decodeCh {
			select {
			case <-w.ctx.Done():
				return
			default:
			}

			err := w.wrap(func() error {
				return w.Parse(w.ctx, v)
			})

			if err != nil {
				w.setError(err, false)
				return
			}
			w.doneCounter.Add(1)

			if w.doneCounter.CompareAndSwap(w.counter.Load(), 0) {
				w.doneCh <- struct{}{}
			}
		}
	}()

	for {
		select {
		case prefixAndName := <-w.nameCh:
			go func() {
				select {
				case <-w.ctx.Done():
					return
				default:
				}

				var reader io.Reader
				v := NewVulnerability(prefixAndName[0])

				err := w.wrap(func() (err error) {
					reader, err = w.Object(prefixAndName[1]).NewReader(w.ctx)
					if err != nil {
						return err
					}

					decoder := json.NewDecoder(reader)

					if err := decoder.Decode(v); err != nil {
						return err
					}

					return nil
				})

				if err != nil {
					w.setError(err, false)
					return
				}

				for _, filter := range w.filters {
					if ok, err := filter.Filter(w.ctx, v); err != nil {
						w.setError(err, false)
						return
					} else if ok {
						return
					}
				}

				w.counter.Add(1)
				w.decodeCh <- v
			}()
		case <-w.doneCh:
			return w.err
		case <-w.ctx.Done():
			return w.ctx.Err()
		}
	}
}

func (w *Worker) Close() {
	close(w.doneCh)
	close(w.decodeCh)
	close(w.nameCh)
	close(w.token)
}
