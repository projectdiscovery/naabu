package runner

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"io"
	"strconv"
	"strings"
)

// JSONResult contains the result for a host in JSON format
type JSONResult struct {
	Host string `json:"host,omitempty" csv:"host"`
	IP   string `json:"ip,omitempty" csv:"ip"`
	Port int    `json:"port" csv:"port"`
}

// WriteHostOutput writes the output list of host ports to an io.Writer
func WriteHostOutput(host string, ports map[int]struct{}, writer io.Writer) error {
	bufwriter := bufio.NewWriter(writer)
	sb := &strings.Builder{}

	for port := range ports {
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
func WriteJSONOutput(host, ip string, ports map[int]struct{}, writer io.Writer) error {
	encoder := json.NewEncoder(writer)

	data := JSONResult{}
	if host != ip {
		data.Host = host
	}
	data.IP = ip

	for port := range ports {
		data.Port = port
		err := encoder.Encode(&data)
		if err != nil {
			return err
		}
	}
	return nil
}

// WriteCsvOutput writes the output list of subdomain in csv format to an io.Writer
func WriteCsvOutput(host, ip string, ports map[int]struct{}, header bool, writer io.Writer) error {
	encoder := csv.NewWriter(writer)
	data := JSONResult{}
	if header {
		getHeader(data, encoder)
	}
	if host != ip {
		data.Host = host
	}
	data.IP = ip

	for port := range ports {
		data.Port = port
		getRows(data, encoder)
	}
	encoder.Flush()
	return nil
}
