package logging

import (
	"fmt"
	json "github.com/90poe/service-chassis/jsonx"
	log "github.com/sirupsen/logrus"
	"time"
)

// Default key names for the default fields
const (
	FieldKeyMsg   = "msg"
	FieldKeyLevel = "level"
	FieldKeyTime  = "time"

	defaultTimestampFormat = time.RFC3339
)

type FieldMap map[fieldKey]string //nolint: golint

type fieldKey string

//JSONFormatter is a custom JSON formatter that can serialise any struct
type JSONFormatter struct {
	TimestampFormat string

	// FieldMap allows users to customize the names of keys for default fields.
	// As an example:
	// formatter := &JSONFormatter{
	//   	FieldMap: FieldMap{
	// 		 FieldKeyTime: "@timestamp",
	// 		 FieldKeyLevel: "@level",
	// 		 FieldKeyMsg: "@message",
	//    },
	// }
	FieldMap FieldMap

	// Indent if not null will cause the formatter to output indented JSON using the supplied indent string, typically some whitespace
	Indent bool

	// DisableTimestamp allows disabling automatic timestamps in output
	DisableTimestamp bool
}

// Format renders a single log entry
func (f *JSONFormatter) Format(entry *log.Entry) ([]byte, error) {
	data := make(log.Fields, len(entry.Data)+3)
	for k, v := range entry.Data {
		switch v := v.(type) {
		case error:
			// Otherwise errors are ignored by `encoding/json`
			// https://github.com/sirupsen/logrus/issues/137
			data[k] = v.Error()
		default:
			data[k] = v
		}
	}

	prefixFieldClashes(data)

	timestampFormat := f.TimestampFormat
	if timestampFormat == "" {
		timestampFormat = defaultTimestampFormat
	}

	if !f.DisableTimestamp {
		data[resolve(f.FieldMap, FieldKeyTime)] = entry.Time.Format(timestampFormat)
	}
	data[resolve(f.FieldMap, FieldKeyMsg)] = entry.Message
	data[resolve(f.FieldMap, FieldKeyLevel)] = entry.Level.String()

	var (
		serialized []byte
		err        error
	)

	if f.Indent {
		serialized, err = json.MarshalIndentWithOptions(data, "", "  ", json.MarshalOptions{SkipUnserializableFields: true})
	} else {
		serialized, err = json.MarshalWithOptions(data, json.MarshalOptions{SkipUnserializableFields: true})
	}

	if err != nil {
		return nil, fmt.Errorf("Failed to marshal fields to JSON, %v", err)
	}

	return append(serialized, '\n'), nil
}

func resolve(f FieldMap, key fieldKey) string {
	if k, ok := f[key]; ok {
		return k
	}

	return string(key)
}

// This is to not silently overwrite `time`, `msg` and `level` fields when
// dumping it. If this code wasn't there doing:
//
//  logrus.WithField("level", 1).Info("hello")
//
// Would just silently drop the user provided level. Instead with this code
// it'll logged as:
//
//  {"level": "info", "fields.level": 1, "msg": "hello", "time": "..."}
//
// It's not exported because it's still using Data in an opinionated way. It's to
// avoid code duplication between the two default formatters.
func prefixFieldClashes(data log.Fields) {
	if t, ok := data["time"]; ok {
		data["fields.time"] = t
	}

	if m, ok := data["msg"]; ok {
		data["fields.msg"] = m
	}

	if l, ok := data["level"]; ok {
		data["fields.level"] = l
	}
}
