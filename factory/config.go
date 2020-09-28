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
	Scheme       string `yaml:"scheme"`
	RegisterIPv4 string `yaml:"registerIPv4,omitempty"` // IP that is registered at NRF.
	// IPv6Addr  string `yaml:"ipv6Addr,omitempty"`
	BindingIPv4 string `yaml:"bindingIPv4,omitempty"` // IP used to run the server in the node.
	Port        int    `yaml:"port,omitempty"`
}
