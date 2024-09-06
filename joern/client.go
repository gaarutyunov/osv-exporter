package joern

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"golang.org/x/net/websocket"
	"net/http"
	"strings"
	"time"
)

type (
	client struct {
		http    *http.Client
		ws      *websocket.Conn
		baseURL string
	}

	QueryRequest struct {
		Query string `json:"query"`
	}

	QueryResponse struct {
		UUID uuid.UUID `json:"uuid"`
	}

	Bool bool

	ResultResponse struct {
		Success bool   `json:"success"`
		Stdout  string `json:"stdout"`
		Stderr  string `json:"stderr"`
	}

	Client interface {
		Open(ctx context.Context) error
		Close(ctx context.Context) error
		Send(ctx context.Context, query string) (QueryResponse, error)
		Result(ctx context.Context, uuid uuid.UUID) (ResultResponse, error)
		Receive(ctx context.Context) (string, error)
	}
)

func NewClient(baseURL, user, pass string) Client {
	return &client{http: &http.Client{
		Timeout: defaultTimeout,
		Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			transport := http.DefaultTransport

			request.URL.Scheme = "http"
			request.URL.Host = baseURL

			if strings.TrimSpace(user) != "" && strings.TrimSpace(pass) != "" {
				request.SetBasicAuth(user, pass)
			}

			return transport.RoundTrip(request)
		}),
	}, baseURL: baseURL}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (r roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return r(request)
}

func (c *client) Open(ctx context.Context) (err error) {
	config, err := websocket.NewConfig("ws://"+c.baseURL+"/connect", "ws://"+c.baseURL+"/connect")
	if err != nil {
		return err
	}
	c.ws, err = config.DialContext(ctx)
	return
}

func (c *client) Close(ctx context.Context) (err error) {
	err = c.ws.Close()
	if err != nil {
		return
	}

	c.ws = nil

	return
}

func (c *client) Send(ctx context.Context, query string) (response QueryResponse, err error) {
	pl := QueryRequest{Query: query}

	body, err := json.Marshal(pl)
	if err != nil {
		return
	}

	res, err := c.http.Post("/query", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		err = errors.New(res.Status)
		return
	}

	err = json.NewDecoder(res.Body).Decode(&response)
	if err != nil {
		return
	}

	return
}

func (c *client) Result(ctx context.Context, uuid uuid.UUID) (result ResultResponse, err error) {
	res, err := c.http.Get("/result/" + uuid.String())
	if err != nil {
		return
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		err = errors.New(res.Status)
		return
	}

	err = json.NewDecoder(res.Body).Decode(&result)
	if err != nil {
		return
	}

	return
}

func (c *client) Receive(ctx context.Context) (m string, err error) {
	err = websocket.Message.Receive(c.ws, &m)

	return
}

const Connected string = "connected"

const defaultTimeout = 3600 * time.Second
