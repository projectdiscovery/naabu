package runner

import (
	"os"

	"gopkg.in/yaml.v3"
)

// MultipleKeyPartsLength is the max length for multiple keys
const MultipleKeyPartsLength = 2

// YAMLIndentCharLength number of chars for identation on write YAML to file
const YAMLIndentCharLength = 4

// ConfigFile contains the fields stored in the configuration file
type ConfigFile struct {
	// Retries is the number of retries for the port
	Retries int `yaml:"retries,omitempty"`
	// Rate is the rate of port scan requests
	Rate int `yaml:"rate,omitempty"`
	// Thread controls the number of parallel host to enumerate
	Threads int `yaml:"threads,omitempty"`
	// Timeout is the seconds to wait for ports to respond
	Timeout int `yaml:"timeout,omitempty"`
	// Hosts are the host to find ports for
	Host []string `yaml:"host,omitempty"`
	// Ports is the ports to use for enumeration
	Ports []string `yaml:"ports,omitempty"`
	// ExcludePorts is the list of ports to exclude from enumeration
	ExcludePorts []string `yaml:"exclude-ports,omitempty"`
	// Verify is used to check if the ports found were valid using CONNECT method
	Verify bool `yaml:"verify,omitempty"`
	// NoProbe skips probes to discover alive hosts
	NoProbe bool `yaml:"no-probe,omitempty"`
	// Ping uses ping probes to discover fastest active host and discover dead hosts
	Ping bool `yaml:"ping,omitempty"`
	// Port Probes (SYN-PORT, ACK-PORT)
	PortProbes []string `yaml:"port-probes,omitempty"`
	// Ips or cidr to be excluded from the scan
	ExcludeIps []string `yaml:"exclude-ips,omitempty"`
	// Top ports list
	TopPorts string `yaml:"top-ports,omitempty"`
	// Attempts to run as root
	Privileged bool `yaml:"privileged,omitempty"`
	// Drop root privileges
	Unprivileged bool `yaml:"unprivileged,omitempty"`
	// Excludes ip of knows CDN ranges
	ExcludeCDN bool `yaml:"exclude-cdn,omitempty"`
	// IcmpEchoProbe before scanning
	IcmpEchoProbe bool `yaml:"icmp-echo-probe,omitempty"`
	// IcmpTimestampProbe before scanning
	IcmpTimestampProbe bool `yaml:"icmp-timestamp-probe,omitempty"`
	// SourceIp to use in TCP packets
	SourceIp string `yaml:"source-ip,omitempty"`
	// Interface to use for TCP packets
	Interface string `yaml:"interface,omitempty"`
	// WarmUpTime between scan phases
	WarmUpTime int `yaml:"warm-up-time,omitempty"`
}

// GetConfigDirectory gets the subfinder config directory for a user
func GetConfigDirectory() (string, error) {
	var config string

	directory, err := os.UserHomeDir()
	if err != nil {
		return config, err
	}
	config = directory + "/.config/naabu"

	// Create All directory for naabu even if they exist
	err = os.MkdirAll(config, os.ModePerm)
	if err != nil {
		return config, err
	}

	return config, nil
}

// CheckConfigExists checks if the config file exists in the given path
func CheckConfigExists(configPath string) bool {
	if _, err := os.Stat(configPath); err == nil {
		return true
	} else if os.IsNotExist(err) {
		return false
	}
	return false
}

// MarshalWrite writes the marshaled yaml config to disk
func (c *ConfigFile) MarshalWrite(file string) error {
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE, 0755)
	if err != nil {
		return err
	}

	// Indent the spaces too
	enc := yaml.NewEncoder(f)
	enc.SetIndent(YAMLIndentCharLength)
	err = enc.Encode(&c)
	f.Close()
	return err
}

// UnmarshalRead reads the unmarshalled config yaml file from disk
func UnmarshalRead(file string) (ConfigFile, error) {
	config := ConfigFile{}

	f, err := os.Open(file)
	if err != nil {
		return config, err
	}
	err = yaml.NewDecoder(f).Decode(&config)
	f.Close()
	return config, err
}
