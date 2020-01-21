package runner

import (
	"bufio"
	"io"
	"strconv"
	"strings"

	jsoniter "github.com/json-iterator/go"
)

// JSONResult contains the result for a host in JSON format
type JSONResult struct {
	Host string `json:"host"`
	Port int    `json:"ip"`
}

// WriteHostOutput writes the output list of host ports to an io.Writer
func WriteHostOutput(host string, results map[int]struct{}, writer io.Writer) error {
	bufwriter := bufio.NewWriter(writer)
	sb := &strings.Builder{}

	for port := range results {
		sb.WriteString(host)
		sb.WriteString(":")
		sb.WriteString(strconv.Itoa(port))
		sb.WriteString("\n")

		_, err := bufwriter.WriteString(sb.String())
		if err != nil {
			bufwriter.Flush()
			return err
		}
		sb.Reset()
	}
	return bufwriter.Flush()
}

// WriteJSONOutput writes the output list of subdomain in JSON to an io.Writer
func WriteJSONOutput(host string, results map[int]struct{}, writer io.Writer) error {
	encoder := jsoniter.NewEncoder(writer)

	data := JSONResult{}
	data.Host = host

	for port := range results {
		data.Port = port

		err := encoder.Encode(&data)
		if err != nil {
			return err
		}
	}
	return nil
}
