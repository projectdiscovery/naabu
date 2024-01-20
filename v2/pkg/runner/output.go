package runner

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"

	"golang.org/x/exp/slices"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
)

// Result contains the result for a host
type Result struct {
	Host      string    `json:"host,omitempty" csv:"host"`
	IP        string    `json:"ip,omitempty" csv:"ip"`
	Port      int       `json:"port,omitempty" csv:"port"`
	Protocol  string    `json:"protocol,omitempty" csv:"protocol"`
	TLS       bool      `json:"tls,omitempty" csv:"tls"`
	IsCDNIP   bool      `json:"cdn,omitempty" csv:"cdn"`
	CDNName   string    `json:"cdn-name,omitempty" csv:"cdn-name"`
	TimeStamp time.Time `json:"timestamp,omitempty" csv:"timestamp"`
}

type jsonResult struct {
	Result
	PortNumber int    `json:"port"`
	Protocol   string `json:"protocol"`
	TLS        bool   `json:"tls"`
}

func (r *Result) JSON() ([]byte, error) {
	data := jsonResult{}
	data.TimeStamp = r.TimeStamp
	if r.Host != r.IP {
		data.Host = r.Host
	}
	data.IP = r.IP
	data.IsCDNIP = r.IsCDNIP
	data.CDNName = r.CDNName
	data.PortNumber = r.Port
	data.Protocol = r.Protocol
	data.TLS = r.TLS

	return json.Marshal(data)
}

var (
	NumberOfCsvFieldsErr = errors.New("exported fields don't match csv tags")
	headers              = []string{}
)

func (r *Result) CSVHeaders() ([]string, error) {
	ty := reflect.TypeOf(*r)
	for i := 0; i < ty.NumField(); i++ {
		field := ty.Field(i)
		csvTag := field.Tag.Get("csv")
		if !slices.Contains(headers, csvTag) {
			headers = append(headers, csvTag)
		}
	}
	return headers, nil
}

func (r *Result) CSVFields() ([]string, error) {
	var fields []string
	vl := reflect.ValueOf(*r)
	ty := reflect.TypeOf(*r)
	for i := 0; i < vl.NumField(); i++ {
		field := vl.Field(i)
		csvTag := ty.Field(i).Tag.Get("csv")
		fieldValue := field.Interface()
		if slices.Contains(headers, csvTag) {
			fields = append(fields, fmt.Sprint(fieldValue))
		}
	}
	return fields, nil
}

// WriteHostOutput writes the output list of host ports to an io.Writer
func WriteHostOutput(host string, ports []*port.Port, outputCDN bool, cdnName string, writer io.Writer) error {
	bufwriter := bufio.NewWriter(writer)
	sb := &strings.Builder{}

	for _, p := range ports {
		sb.WriteString(host)
		sb.WriteString(":")
		sb.WriteString(strconv.Itoa(p.Port))
		if outputCDN && cdnName != "" {
			sb.WriteString(" [" + cdnName + "]")
		}
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
func WriteJSONOutput(host, ip string, ports []*port.Port, outputCDN bool, isCdn bool, cdnName string, writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	data := jsonResult{}
	data.TimeStamp = time.Now().UTC()
	if host != ip {
		data.Host = host
	}
	data.IP = ip
	if outputCDN {
		data.IsCDNIP = isCdn
		data.CDNName = cdnName
	}
	for _, p := range ports {
		data.PortNumber = p.Port
		data.Protocol = p.Protocol.String()
		data.TLS = p.TLS
		if err := encoder.Encode(&data); err != nil {
			return err
		}
	}
	return nil
}

// WriteCsvOutput writes the output list of subdomain in csv format to an io.Writer
func WriteCsvOutput(host, ip string, ports []*port.Port, outputCDN bool, isCdn bool, cdnName string, header bool, writer io.Writer) error {
	encoder := csv.NewWriter(writer)
	data := &Result{IP: ip, TimeStamp: time.Now().UTC(), Port: 0, Protocol: protocol.TCP.String(), TLS: false}
	if host != ip {
		data.Host = host
	}
	if outputCDN {
		data.IsCDNIP = isCdn
		data.CDNName = cdnName
	}
	if header {
		writeCSVHeaders(data, encoder)
	}

	for _, p := range ports {
		data.Port = p.Port
		data.Protocol = p.Protocol.String()
		data.TLS = p.TLS
		writeCSVRow(data, encoder)
	}
	encoder.Flush()
	return nil
}

func writeCSVHeaders(data *Result, writer *csv.Writer) {
	headers, err := data.CSVHeaders()
	if err != nil {
		gologger.Error().Msgf(err.Error())
		return
	}

	if err := writer.Write(headers); err != nil {
		errMsg := errors.Wrap(err, "Could not write headers")
		gologger.Error().Msgf(errMsg.Error())
	}
}

func writeCSVRow(data *Result, writer *csv.Writer) {
	rowData, err := data.CSVFields()
	if err != nil {
		gologger.Error().Msgf(err.Error())
		return
	}
	if err := writer.Write(rowData); err != nil {
		errMsg := errors.Wrap(err, "Could not write row")
		gologger.Error().Msgf(errMsg.Error())
	}
}
