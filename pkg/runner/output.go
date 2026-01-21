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
	"github.com/projectdiscovery/utils/structs"
)

// Result contains the result for a host
type Result struct {
	Host       string    `json:"host,omitempty" csv:"host"`
	IP         string    `json:"ip,omitempty" csv:"ip"`
	Port       int       `json:"port,omitempty" csv:"port"`
	Protocol   string    `json:"protocol,omitempty" csv:"protocol"`
	TLS        bool      `json:"tls,omitempty" csv:"tls"`
	IsCDNIP    bool      `json:"cdn,omitempty" csv:"cdn"`
	CDNName    string    `json:"cdn-name,omitempty" csv:"cdn-name"`
	TimeStamp  time.Time `json:"timestamp,omitempty" csv:"timestamp"`
	MacAddress string    `json:"mac_address,omitempty" csv:"mac_address"`

	// TODO: flattening fields should be fully reworked to reuse nested structs
	// just add the service flat structure
	DeviceType  string `json:"device_type,omitempty"`
	ExtraInfo   string `json:"extra_info,omitempty"`
	HighVersion string `json:"high_version,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	LowVersion  string `json:"low_version,omitempty"`
	Method      string `json:"method,omitempty"`
	Name        string `json:"name,omitempty"`
	OSType      string `json:"os_type,omitempty"`
	Product     string `json:"product,omitempty"`
	Proto       string `json:"proto,omitempty"`
	RPCNum      string `json:"rpc_num,omitempty"`
	ServiceFP   string `json:"service_fp,omitempty"`
	Tunnel      string `json:"tunnel,omitempty"`
	Version     string `json:"version,omitempty"`
	Confidence  int    `json:"confidence,omitempty"`
}

// TODO:
// - Many structures like the following one appears redundant and to complicate the codebase
// - Dynamic fields filtering seems to be out of scope of the tool, complicating output handling
type jsonResult struct {
	Host       string    `json:"host,omitempty" csv:"host"`
	IP         string    `json:"ip,omitempty" csv:"ip"`
	IsCDNIP    bool      `json:"cdn,omitempty" csv:"cdn"`
	CDNName    string    `json:"cdn-name,omitempty" csv:"cdn-name"`
	TimeStamp  time.Time `json:"timestamp,omitempty" csv:"timestamp"`
	Port       int       `json:"port"`
	Protocol   string    `json:"protocol"`
	TLS        bool      `json:"tls"`
	MacAddress string    `json:"mac_address,omitempty" csv:"mac_address"`

	// TODO: flattening fields should be fully reworked to reuse nested structs
	// just add the service flat structure
	DeviceType  string `json:"device_type,omitempty"`
	ExtraInfo   string `json:"extra_info,omitempty"`
	HighVersion string `json:"high_version,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	LowVersion  string `json:"low_version,omitempty"`
	Method      string `json:"method,omitempty"`
	Name        string `json:"name,omitempty"`
	OSType      string `json:"os_type,omitempty"`
	Product     string `json:"product,omitempty"`
	Proto       string `json:"proto,omitempty"`
	RPCNum      string `json:"rpc_num,omitempty"`
	ServiceFP   string `json:"service_fp,omitempty"`
	Tunnel      string `json:"tunnel,omitempty"`
	Version     string `json:"version,omitempty"`
	Confidence  int    `json:"confidence,omitempty"`
}

func (r *Result) JSON(excludedFields []string) ([]byte, error) {
	data := jsonResult{}
	data.TimeStamp = r.TimeStamp
	if r.Host != r.IP {
		data.Host = r.Host
	}
	data.IP = r.IP
	data.IsCDNIP = r.IsCDNIP
	data.CDNName = r.CDNName
	data.Port = r.Port
	data.Protocol = r.Protocol
	data.TLS = r.TLS
	data.MacAddress = r.MacAddress

	// copy the service fields
	data.DeviceType = r.DeviceType
	data.ExtraInfo = r.ExtraInfo
	data.HighVersion = r.HighVersion
	data.Hostname = r.Hostname
	data.LowVersion = r.LowVersion
	data.Method = r.Method
	data.Name = r.Name
	data.OSType = r.OSType
	data.Product = r.Product
	data.Proto = r.Proto
	data.RPCNum = r.RPCNum
	data.ServiceFP = r.ServiceFP
	data.Tunnel = r.Tunnel
	data.Version = r.Version
	data.Confidence = r.Confidence

	if len(excludedFields) == 0 {
		return json.Marshal(data)
	}

	filteredMap, err := structs.FilterStructToMap(data, nil, excludedFields)
	if err != nil {
		return nil, err
	}

	return json.Marshal(filteredMap)
}

var (
	NumberOfCsvFieldsErr = errors.New("exported fields don't match csv tags")
	headers              = []string{}
)

func (r *Result) CSVHeaders(excludedFields []string) ([]string, error) {
	ty := reflect.TypeOf(*r)
	for i := 0; i < ty.NumField(); i++ {
		field := ty.Field(i)
		csvTag := field.Tag.Get("csv")
		if !slices.Contains(headers, csvTag) && !slices.Contains(excludedFields, csvTag) {
			headers = append(headers, csvTag)
		}
	}
	return headers, nil
}

func (r *Result) CSVFields(excludedFields []string) ([]string, error) {
	data := *r
	if len(excludedFields) > 0 {
		if filteredData, err := structs.FilterStruct(data, nil, excludedFields); err == nil {
			data = filteredData
		}
	}

	var fields []string
	vl := reflect.ValueOf(data)
	ty := reflect.TypeOf(data)
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
			_ = bufwriter.Flush()
			return err
		}
		sb.Reset()
	}
	return bufwriter.Flush()
}

// WriteJSONOutput writes the output list of subdomain in JSON to an io.Writer
func WriteJSONOutput(host, ip string, ports []*port.Port, outputCDN bool, isCdn bool, cdnName string, excludedFields []string, writer io.Writer) error {
	return WriteJSONOutputWithMac(host, ip, "", ports, outputCDN, isCdn, cdnName, excludedFields, writer)
}

// WriteJSONOutputWithMac writes the output list of subdomain in JSON to an io.Writer with MAC address
func WriteJSONOutputWithMac(host, ip, macAddress string, ports []*port.Port, outputCDN bool, isCdn bool, cdnName string, excludedFields []string, writer io.Writer) error {
	result := &Result{
		Host:       host,
		IP:         ip,
		MacAddress: macAddress,
		TimeStamp:  time.Now().UTC(),
	}
	if outputCDN {
		result.IsCDNIP = isCdn
		result.CDNName = cdnName
	}

	if len(ports) == 0 {
		b, err := result.JSON(excludedFields)
		if err != nil {
			return err
		}
		_, err = writer.Write(append(b, '\n'))
		return err
	}

	for _, p := range ports {
		result.Port = p.Port
		result.Protocol = p.Protocol.String()
		//nolint
		result.TLS = p.TLS

		copyServiceFields(result, p.Service)

		b, err := result.JSON(excludedFields)
		if err != nil {
			return err
		}

		if _, err := writer.Write(append(b, '\n')); err != nil {
			return err
		}
	}
	return nil
}

// WriteCsvOutput writes the output list of subdomain in csv format to an io.Writer
func WriteCsvOutput(host, ip string, ports []*port.Port, outputCDN bool, isCdn bool, cdnName string, header bool, excludedFields []string, writer io.Writer) error {
	return WriteCsvOutputWithMac(host, ip, "", ports, outputCDN, isCdn, cdnName, header, excludedFields, writer)
}

// WriteCsvOutputWithMac writes the output list of subdomain in csv format to an io.Writer with MAC address
func WriteCsvOutputWithMac(host, ip, macAddress string, ports []*port.Port, outputCDN bool, isCdn bool, cdnName string, header bool, excludedFields []string, writer io.Writer) error {
	encoder := csv.NewWriter(writer)
	data := &Result{IP: ip, MacAddress: macAddress, TimeStamp: time.Now().UTC(), Port: 0, Protocol: protocol.TCP.String(), TLS: false}
	if host != ip {
		data.Host = host
	}
	if outputCDN {
		data.IsCDNIP = isCdn
		data.CDNName = cdnName
	}
	if header {
		writeCSVHeaders(data, encoder, excludedFields)
	}

	if len(ports) == 0 {
		writeCSVRow(data, encoder, excludedFields)
	} else {
		for _, p := range ports {
			data.Port = p.Port
			data.Protocol = p.Protocol.String()
			//nolint
			data.TLS = p.TLS

			copyServiceFields(data, p.Service)

			writeCSVRow(data, encoder, excludedFields)
		}
	}
	encoder.Flush()
	return nil
}

func writeCSVHeaders(data *Result, writer *csv.Writer, excludedFields []string) {
	headers, err := data.CSVHeaders(excludedFields)
	if err != nil {
		gologger.Error().Msg(err.Error())
		return
	}

	if err := writer.Write(headers); err != nil {
		errMsg := errors.Wrap(err, "Could not write headers")
		gologger.Error().Msg(errMsg.Error())
	}
}

func writeCSVRow(data *Result, writer *csv.Writer, excludedFields []string) {
	rowData, err := data.CSVFields(excludedFields)
	if err != nil {
		gologger.Error().Msg(err.Error())
		return
	}
	if err := writer.Write(rowData); err != nil {
		errMsg := errors.Wrap(err, "Could not write row")
		gologger.Error().Msg(errMsg.Error())
	}
}

// copyServiceFields copies all service fields from service to result, or clears them if service is nil.
func copyServiceFields(result *Result, service *port.Service) {
	var s *port.Service
	if service != nil {
		s = service
	} else {
		s = &port.Service{}
	}

	result.DeviceType = s.DeviceType
	result.ExtraInfo = s.ExtraInfo
	result.HighVersion = s.HighVersion
	result.Hostname = s.Hostname
	result.LowVersion = s.LowVersion
	result.Method = s.Method
	result.Name = s.Name
	result.OSType = s.OSType
	result.Product = s.Product
	result.Proto = s.Proto
	result.RPCNum = s.RPCNum
	result.ServiceFP = s.ServiceFP
	result.Tunnel = s.Tunnel
	result.Version = s.Version
	result.Confidence = s.Confidence
}