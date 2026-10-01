package utils

import (
	"os"
	"strings"
)

// Getenv returns the environment variable key, or def when it is unset or empty.
func Getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// KafkaBrokers returns the comma-separated KAFKA_BROKERS list (default localhost:9092).
func KafkaBrokers() []string {
	return strings.Split(Getenv("KAFKA_BROKERS", "localhost:9092"), ",")
}
