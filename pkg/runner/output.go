package runner

import (
	"encoding/json"
	"fmt"
	"io"
)

// JSONResult contains the result for a host in JSON format
type JSONResult struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// WriteHostOutput writes the output list of host ports to an io.Writer
func WriteHostOutput(host string, ports map[int]struct{}, writer io.Writer) error {
	for port := range ports {
		_, err := fmt.Fprintf(writer, "%s:%d\n", host, port)
		if err != nil {
			return err
		}
	}
	return nil
}

// WriteJSONOutput writes the output list of subdomain in JSON to an io.Writer
func WriteJSONOutput(host string, ports map[int]struct{}, writer io.Writer) error {
	encoder := json.NewEncoder(writer)

	data := JSONResult{}
	data.Host = host

	for port := range ports {
		data.Port = port

		err := encoder.Encode(&data)
		if err != nil {
			return err
		}
	}
	return nil
}
