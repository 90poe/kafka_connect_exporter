package env

import (
	"github.com/spf13/viper"
)

type Config struct {
	ListenAddress string //Address on which to expose metrics.
	TelemetryPath string //Path under which to expose metrics.
	ScrapeURI     string //URI on which to scrape kafka connect.
}

var Settings Config

func init() {
	viper.AutomaticEnv()

	viper.SetEnvPrefix("APP")
	viper.SetDefault("LISTEN_ADDRESS", ":8080")
	viper.SetDefault("TELEMETRY_PATH", "/metrics")
	viper.SetDefault("SCRAPE_URI", "http://127.0.0.1:8080")

	Settings = Config{
		ListenAddress: viper.GetString("LISTEN_ADDRESS"),
		TelemetryPath: viper.GetString("TELEMETRY_PATH"),
		ScrapeURI:     viper.GetString("SCRAPE_URI"),
	}

}
