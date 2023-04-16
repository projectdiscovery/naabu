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

	"github.com/pkg/errors"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
)

// Result contains the result for a host
type Result struct {
	Host      string     `json:"host,omitempty" csv:"host"`
	IP        string     `json:"ip,omitempty" csv:"ip"`
	Port      *port.Port `json:"port" csv:"port"`
	IsCDNIP   bool       `json:"cdn,omitempty" csv:"cdn"`
	CDNName   string     `json:"cdn-name,omitempty" csv:"cdn-name"`
	TimeStamp time.Time  `json:"timestamp" csv:"timestamp"`
}

func (r *Result) JSON() ([]byte, error) {
	return json.Marshal(r)
}

var NumberOfCsvFieldsErr = errors.New("exported fields don't match csv tags")

func (r *Result) CSVHeaders() ([]string, error) {
	ty := reflect.TypeOf(*r)
	var headers []string
	for i := 0; i < ty.NumField(); i++ {
		field := ty.Field(i)
		csvTag := field.Tag.Get("csv")
		fieldValue := reflect.ValueOf(*r).FieldByName(field.Name).Interface()
		// appends tag value if field value is other than default value
		if fieldValue != reflect.Zero(field.Type).Interface() {
			headers = append(headers, csvTag)
		}
	}
	return headers, nil
}

func (r *Result) CSVFields() ([]string, error) {
	var fields []string
	vl := reflect.ValueOf(*r)
	for i := 0; i < vl.NumField(); i++ {
		field := vl.Field(i)
		fieldValue := field.Interface()
		zeroValue := reflect.Zero(field.Type()).Interface()
		// appends tag value if field value is other than default value
		if !reflect.DeepEqual(fieldValue, zeroValue) {
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
	data := Result{TimeStamp: time.Now().UTC()}
	if host != ip {
		data.Host = host
	}
	data.IP = ip
	if outputCDN {
		data.IsCDNIP = isCdn
		data.CDNName = cdnName
	}
	for _, p := range ports {
		data.Port = p
		if err := encoder.Encode(&data); err != nil {
			return err
		}
	}
	return nil
}

// WriteCsvOutput writes the output list of subdomain in csv format to an io.Writer
func WriteCsvOutput(host, ip string, ports []*port.Port, outputCDN bool, isCdn bool, cdnName string, header bool, writer io.Writer) error {
	encoder := csv.NewWriter(writer)
	data := &Result{IP: ip, TimeStamp: time.Now().UTC(), Port: &port.Port{}}
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
		data.Port = p
		writeCSVRow(data, encoder)
	}
	encoder.Flush()
	return nil
}
