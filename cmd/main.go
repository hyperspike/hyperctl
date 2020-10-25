package main

import (
	"os"
	"io"
	log "github.com/sirupsen/logrus"
	"hyperspike.io/hyperctl/cmd/commands"
)
func init() {
	logFile, err := os.OpenFile("/tmp/hyperspike.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	// defer logFile.Close()
	mw := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(mw)
	log.SetFormatter(&log.TextFormatter{
		DisableColors: false,
		FullTimestamp: true,
	})
}
func main() {

	commands.Execute()
}
