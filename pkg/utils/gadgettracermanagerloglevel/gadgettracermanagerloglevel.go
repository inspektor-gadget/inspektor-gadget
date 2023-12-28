package gadgettracermanagerloglevel

import (
	log "github.com/sirupsen/logrus"
	"os"
	"sync"
)

var (
	loglevel log.Level
	once     sync.Once
)

const EnvName = "GADGET_TRACER_MANAGER_LOG_LEVEL"

func LogLevel() log.Level {
	once.Do(func() {
		if val, ok := os.LookupEnv(EnvName); ok {
			if level, parseErr := log.ParseLevel(val); parseErr == nil {
				loglevel = level
				return
			}
		}
		loglevel = log.InfoLevel
	})

	return loglevel
}
