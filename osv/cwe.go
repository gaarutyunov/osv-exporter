package osv

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

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
