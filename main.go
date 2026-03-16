package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"hikvision-control/internal/common"
	"hikvision-control/internal/config"
	"hikvision-control/internal/control"
	"hikvision-control/internal/hikvision"

	"github.com/multiversx/mx-chain-core-go/core/check"
	logger "github.com/multiversx/mx-chain-logger-go"
	"github.com/urfave/cli"
)

const (
	envFile              = "./.env"
	configFile           = "./config.toml"
	defaultLogsPath      = "logs"
	logFilePrefix        = "control"
	logFileLifeSpanInSec = 86400 // 24h
	logFileLifeSpanInMB  = 1024  // 1GB
)

// appVersion should be populated at build time using ldflags
// Usage examples:
// Linux/macOS:
//
//	go build -v -ldflags="-X main.appVersion=$(git describe --all | cut -c7-32)
var appVersion = "undefined"
var fileLogging common.FileLoggingHandler

var (
	proxyHelpTemplate = `NAME:
   {{.Name}} - {{.Usage}}
USAGE:
   {{.HelpName}} {{if .VisibleFlags}}[global options]{{end}}
   {{if len .Authors}}
AUTHOR:
   {{range .Authors}}{{ . }}{{end}}
   {{end}}{{if .Commands}}
GLOBAL OPTIONS:
   {{range .VisibleFlags}}{{.}}
   {{end}}
VERSION:
   {{.Version}}
   {{end}}
`

	// logLevel defines the logger level
	logLevel = cli.StringFlag{
		Name: "log-level",
		Usage: "This flag specifies the logger `level(s)`. It can contain multiple comma-separated value. For example" +
			", if set to *:INFO the logs for all packages will have the INFO level. However, if set to *:INFO,api:DEBUG" +
			" the logs for all packages will have the INFO level, excepting the api package which will receive a DEBUG" +
			" log level.",
		Value: "*:" + logger.LogInfo.String(),
	}
	// logFile is used when the log output needs to be logged in a file
	logSaveFile = cli.BoolFlag{
		Name:  "log-save",
		Usage: "Boolean option for enabling log saving. If set, it will automatically save all the logs into a file.",
	}
	// workingDirectory defines a flag for the path for the working directory.
	workingDirectory = cli.StringFlag{
		Name:  "working-directory",
		Usage: "This flag specifies the `directory` where the node will store databases and logs.",
		Value: "",
	}

	envFileContents = map[string]string{
		common.EnvUser:     "",
		common.EnvPass:     "",
		common.EnvIP:       "",
		common.EnvChannels: "",
	}

	log = logger.GetOrCreate("hikvision-control")
)

func main() {
	app := cli.NewApp()
	cli.AppHelpTemplate = proxyHelpTemplate
	app.Name = "Hikvision control service"
	app.Version = fmt.Sprintf("%s/%s/%s-%s", appVersion, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	app.Usage = "This is the entry point for starting a new service for controlling Hikvision cameras"
	app.Flags = []cli.Flag{
		logLevel,
		logSaveFile,
		workingDirectory,
	}
	app.Authors = []cli.Author{
		{
			Name:  "Iulian Pascalau",
			Email: "iulian.pascalau@gmail.com",
		},
	}

	app.Action = run

	defer func() {
		if fileLogging != nil {
			_ = fileLogging.Close()
		}
	}()

	err := app.Run(os.Args)
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
}

func run(ctx *cli.Context) error {
	saveLogFile := ctx.GlobalBool(logSaveFile.Name)
	workingDir := ctx.GlobalString(workingDirectory.Name)

	err := logger.SetLogLevel(ctx.GlobalString(logLevel.Name))
	if err != nil {
		return err
	}

	fileLogging, err = common.AttachFileLogger(log, defaultLogsPath, logFilePrefix, saveLogFile, workingDir)
	if err != nil {
		return err
	}

	if !check.IfNil(fileLogging) {
		timeLogLifeSpan := time.Second * time.Duration(logFileLifeSpanInSec)
		sizeLogLifeSpanInMB := uint64(logFileLifeSpanInMB)
		err = fileLogging.ChangeFileLifeSpan(timeLogLifeSpan, sizeLogLifeSpanInMB)
		if err != nil {
			return err
		}
	}

	log.Info("Starting Hikvision control service", "version", appVersion, "pid", os.Getpid())

	err = common.ReadEnvFile(envFile, envFileContents)
	if err != nil {
		return err
	}

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		return err
	}

	client := hikvision.NewClient(envFileContents[common.EnvIP], envFileContents[common.EnvUser], envFileContents[common.EnvPass])
	handler, err := control.NewChannelsHandler(*cfg, client)
	if err != nil {
		return err
	}

	_ = handler

	log.Info("Hikvision control service started")

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	<-sigs

	log.Info("Application closing, calling Close on all subcomponents...")

	return nil
}
