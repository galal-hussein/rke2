package log

import (
	"flag"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/rancher/rke2/pkg/config"
	"github.com/sirupsen/logrus"
)

var (
	LogConfig    config.Log
	logSetupOnce sync.Once
)

func InitLogging() error {
	var rErr error
	logSetupOnce.Do(func() {
		if err := forkIfLoggingOrReaping(); err != nil {
			rErr = err
			return
		}

		if err := checkUnixTimestamp(); err != nil {
			rErr = err
			return
		}

		setupLogging()
	})
	return rErr
}

func checkUnixTimestamp() error {
	timeNow := time.Now()
	// check if time before 01/01/1980
	if timeNow.Before(time.Unix(315532800, 0)) {
		return fmt.Errorf("server time isn't set properly: %v", timeNow)
	}
	return nil
}

func setupLogging() {
	flag.Set("v", strconv.Itoa(LogConfig.VLevel))
	flag.Set("vmodule", LogConfig.VModule)
	flag.Set("alsologtostderr", strconv.FormatBool(LogConfig.Debug))
	flag.Set("logtostderr", strconv.FormatBool(!LogConfig.Debug))
	if LogConfig.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	}
}
