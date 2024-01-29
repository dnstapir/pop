/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tapir

import (
	"log"

	"gopkg.in/natefinch/lumberjack.v2"
)

func SetupLogging(logfile string) error {

	if logfile != "" {
		log.SetOutput(&lumberjack.Logger{
			Filename:   logfile,
			MaxSize:    20,
			MaxBackups: 3,
			MaxAge:     14,
		})
	} else {
		log.Fatalf("Error: standard log (key log.file) not specified")
	}

	return nil
}
