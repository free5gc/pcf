/*
 * PCF Configuration Factory
 */

package factory

import (
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v2"

	"github.com/free5gc/pcf/internal/logger"
)

var PcfConfig Config

// TODO: Support configuration update from REST api
func InitConfigFactory(f string) error {
	if content, err := ioutil.ReadFile(f); err != nil {
		return err
	} else {
		PcfConfig = Config{}

		if yamlErr := yaml.Unmarshal(content, &PcfConfig); yamlErr != nil {
			return yamlErr
		}
	}

	return nil
}

func CheckConfigVersion() error {
	currentVersion := PcfConfig.GetVersion()

	if currentVersion != PcfExpectedConfigVersion {
		return fmt.Errorf("config version is [%s], but expected is [%s].",
			currentVersion, PcfExpectedConfigVersion)
	}

	logger.CfgLog.Infof("config version [%s]", currentVersion)

	return nil
}
