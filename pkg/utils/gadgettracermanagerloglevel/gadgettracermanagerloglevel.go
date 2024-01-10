package gadgettracermanagerloglevel

import (
	"os"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

var (
	loglevel log.Level
	once     sync.Once
)

const EnvName = "GADGET_TRACER_MANAGER_LOG_LEVEL"

func LogLevel() log.Level {
	once.Do(func() {
		strLevels := make([]string, len(log.AllLevels))
		for i, level := range log.AllLevels {
			strLevels[i] = level.String()
		}
		if val, ok := os.LookupEnv(EnvName); ok {
			if level, parseErr := log.ParseLevel(val); parseErr == nil {
				loglevel = level
				return
			} else {
				log.WithError(parseErr).Errorf("Invalid log level, valid levels are: %v, defaulting to %s", strings.Join(strLevels, ", "), log.InfoLevel)
			}
		}
		loglevel = log.InfoLevel
	})

	return loglevel
}
