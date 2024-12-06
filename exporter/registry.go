package exporter

import "fmt"

var exporters = map[string]File{}

func init() {
	Register("meta", Meta())
}

// Register registers exporter to be used for vulnerable files
func Register(name string, exporter File) {
	exporters[name] = exporter
}

// Get gets one of the available exporters by name or returns error if it doesn't exist
func Get(name string) (exporter File, err error) {
	exporter, ok := exporters[name]

	if !ok {
		return nil, fmt.Errorf("exporter %s is invalid", name)
	}

	return
}
