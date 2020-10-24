package main

import (
	"os"
	"io"
	log "github.com/sirupsen/logrus"
	"hyperspike.io/hyperctl/cmd/commands"
)
func init() {
	logFile, err := os.Create("/tmp/hyperspike.log")
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
