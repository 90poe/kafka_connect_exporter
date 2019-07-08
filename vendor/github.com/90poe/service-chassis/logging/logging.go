package logging

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	scctx "github.com/90poe/service-chassis/context"
	"github.com/90poe/service-chassis/correlation"
	log "github.com/sirupsen/logrus"
)

const (
	DEBUG Level = 1 << iota
	INFO
	ERROR

	DefaultStackTraceLogLevel = DEBUG | ERROR
)

var (
	traceLevels *Level
)

type (
	Level byte

	Entry interface {
		Write(args ...interface{})
		Writeln(args ...interface{})
		Writef(format string, args ...interface{})
		WithField(key string, value interface{}) Entry
		WithFields(fields log.Fields) Entry
		Level() Level
		Entry() *log.Entry
	}

	EntryFunc func() Entry

	EntryFromContextFunc func(context.Context) Entry

	entry struct {
		entry             *log.Entry
		level             Level
		instanceAugmenter EntryAugmenter
	}

	EntryAugmenter func(Entry) Entry
)

func Init(level Level, out io.Writer, pretty bool) {
	log.SetFormatter(&JSONFormatter{Indent: pretty})

	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	log.SetOutput(out)

	switch level {
	case DEBUG:
		log.SetLevel(log.DebugLevel)
	case INFO:
		log.SetLevel(log.InfoLevel)
	case ERROR:
		log.SetLevel(log.ErrorLevel)
	}

	traceLevels = LevelPtr(DefaultStackTraceLogLevel)
}

func GetLogLevel() Level {
	switch log.GetLevel() {
	case log.DebugLevel:
		return DEBUG
	case log.InfoLevel:
		return INFO
	case log.ErrorLevel:
		return ERROR
	}

	return INFO
}

func StackTraceLevel() *Level {
	return traceLevels
}

func SetStackTraceLevels(stackTraceLevel Level) {
	traceLevels = LevelPtr(stackTraceLevel)
}

func ClearStackTraceLevels() {
	traceLevels = nil
}

func ParseLevel(level string) (*Level, error) {
	switch strings.ToUpper(strings.Trim(level, "")) {
	case "DEBUG":
		return LevelPtr(DEBUG), nil
	case "INFO":
		return LevelPtr(INFO), nil
	case "ERROR":
		return LevelPtr(ERROR), nil
	default:
		return nil, fmt.Errorf("Unrecognised log level : %v", level)
	}
}

func LevelPtr(level Level) *Level {
	return &level
}

func (entry *entry) Level() Level {
	return entry.level
}

func (entry *entry) Entry() *log.Entry {
	return entry.entry
}

func (entry *entry) Write(args ...interface{}) {
	etry := addInstanceFields(entry, args)
	switch etry.Level() {
	case DEBUG:
		etry.Entry().Debug(args...)
	case ERROR:
		etry.Entry().Error(args...)
	case INFO:
		etry.Entry().Info(args...)
	}
}

func (entry *entry) Writeln(args ...interface{}) {
	etry := addInstanceFields(entry, args)
	switch etry.Level() {
	case DEBUG:
		etry.Entry().Debugln(args...)
	case ERROR:
		etry.Entry().Errorln(args...)
	case INFO:
		etry.Entry().Infoln(args...)
	}
}

func (entry *entry) Writef(format string, args ...interface{}) {
	etry := addInstanceFields(entry, args)
	switch etry.Level() {
	case DEBUG:
		etry.Entry().Debugf(format, args...)
	case ERROR:
		etry.Entry().Errorf(format, args...)
	case INFO:
		etry.Entry().Infof(format, args...)
	}
}

func addInstanceFields(entry *entry, args []interface{}) Entry {
	var etry Entry = entry
	if traceLevels != nil && ((*traceLevels & entry.level) != 0) {
		for index, arg := range args {
			if err, ok := arg.(error); ok {
				etry = etry.WithField(
					fmt.Sprintf("ErrorStack_%v", index),
					fmt.Sprintf("%+v", err))
			}
		}
	}

	return entry.instanceAugmenter(etry.WithField("epoch", time.Now().Unix()))
}

func (entry *entry) WithField(key string, value interface{}) Entry {
	entry.entry = entry.entry.WithField(key, value)
	return entry
}

func (entry *entry) WithFields(fields log.Fields) Entry {
	entry.entry = entry.entry.WithFields(fields)
	return entry
}

func newLogEntry(level Level, service string, code int, label string, instanceAugmenter EntryAugmenter) Entry {
	return &entry{
		entry: log.NewEntry(log.StandardLogger()).
			WithField("service", service).
			WithField("code", code).
			WithField("label", label),
		level:             level,
		instanceAugmenter: instanceAugmenter,
	}
}

type logEntryFactory struct {
	service           string
	instanceAugmenter EntryAugmenter
}

type LogEntryFactory interface {
	MakeEntry(level Level, code int, label string) EntryFunc
}

func (factory *logEntryFactory) MakeEntry(level Level, code int, label string) EntryFunc {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "failed to determine"
	}

	return func() Entry {
		return newLogEntry(level, factory.service, code, label, factory.instanceAugmenter).
			WithField("hostname", hostname).
			WithField("address", ipAddress())
	}
}

func ipAddress() (address string) {
	address = ""
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			address += addr.String()
		}
	}

	return
}

func (entryFunc EntryFunc) WithCorrelationID(ctx context.Context) Entry {
	entry := entryFunc()

	if correlationID, ok := scctx.GetCorrelationID(ctx); ok {
		entry.WithField(correlation.CorrelationIDFieldName, correlationID)
	}

	return entry
}

func NewLogEntryFactory(service string) LogEntryFactory {
	return NewLogEntryFactoryWithInstanceAugmentation(service, nil)
}

func NewLogEntryFactoryWithInstanceAugmentation(service string, instanceAugmenter EntryAugmenter) LogEntryFactory {

	if instanceAugmenter == nil {
		instanceAugmenter = func(entry Entry) Entry { return entry }
	}

	return &logEntryFactory{service: service, instanceAugmenter: instanceAugmenter}
}
