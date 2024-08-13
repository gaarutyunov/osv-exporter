package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type Severity string

const (
	Unknown  = Severity("")
	Low      = Severity("LOW")
	Medium   = Severity("MEDIUM")
	High     = Severity("HIGH")
	Critical = Severity("CRITICAL")
)

var severityMap = map[Severity]int{
	Unknown:  -1,
	Low:      0,
	Medium:   1,
	High:     2,
	Critical: 3,
}

type DatabaseSpecific struct {
	CWE      []*CWE `json:"cwe_ids"`
	Severity `json:"severity"`
}

type CWE struct {
	ID int `json:"id"`
}

func (C *CWE) MarshalJSON() ([]byte, error) {
	s := fmt.Sprintf("CWE-%d", C.ID)

	return json.Marshal(s)
}

func (C *CWE) UnmarshalJSON(bytes []byte) error {
	var s string

	if err := json.Unmarshal(bytes, &s); err != nil {
		return err
	}

	s = strings.TrimPrefix(s, "CWE-")

	c, err := strconv.Atoi(s)
	if err != nil {
		return err
	}

	C.ID = c

	return nil
}

type (
	URL struct {
		*url.URL
	}

	Reference struct {
		URL URL `json:"url"`
	}
	Vulnerability struct {
		prefix string

		ID               string `json:"id"`
		DatabaseSpecific `json:"database_specific"`
		References       []Reference `json:"references"`
	}
)

func (u *URL) MarshalJSON() ([]byte, error) {
	s := u.String()

	return json.Marshal(s)
}

func (u *URL) UnmarshalJSON(bytes []byte) (err error) {
	var s string

	err = json.Unmarshal(bytes, &s)
	if err != nil {
		return
	}

	u.URL, err = url.Parse(s)

	return
}

func NewVulnerability(prefix string) *Vulnerability {
	return &Vulnerability{prefix: prefix}
}
