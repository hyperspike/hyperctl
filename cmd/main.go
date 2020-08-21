package main

import (
	log "github.com/sirupsen/logrus"
	"hyperspike.io/eng/hyperctl/cmd/commands"
)
func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableColors: false,
		FullTimestamp: true,
	})
}
func main() {

	commands.Execute()
}
