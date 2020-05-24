/*
 * PCF Configuration Factory
 */

package factory

type Config struct {
	Info *Info `yaml:"info"`

	Configuration *Configuration `yaml:"configuration"`
}

type Info struct {
	Version string `yaml:"version,omitempty"`

	Description string `yaml:"description,omitempty"`
}

type Configuration struct {
	PcfName string `yaml:"pcfName,omitempty"`

	Sbi *Sbi `yaml:"sbi,omitempty"`

	TimeFormat string `yaml:"timeFormat,omitempty"`

	DefaultBdtRefId string `yaml:"defaultBdtRefId,omitempty"`

	NrfUri string `yaml:"nrfUri,omitempty"`

	ServiceList []Service `yaml:"serviceList,omitempty"`
}

type Service struct {
	ServiceName string `yaml:"serviceName"`
	SuppFeat    string `yaml:"suppFeat,omitempty"`
}

type Sbi struct {
	Scheme   string `yaml:"scheme"`
	IPv4Addr string `yaml:"ipv4Addr,omitempty"`
	// IPv6Addr string `yaml:"ipv6Addr,omitempty"`
	Port int `yaml:"port,omitempty"`
}
