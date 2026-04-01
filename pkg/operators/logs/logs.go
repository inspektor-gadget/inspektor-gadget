// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logs

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	jsonformatter "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	OperatorName = "logs"
	Priority     = 9998

	ConfigKeyEnabled    = "operator.logs.enabled"
	ConfigKeyChannel    = "operator.logs.channel"
	ConfigKeyFilename   = "operator.logs.filename"
	ConfigKeyFormat     = "operator.logs.format"
	ConfigKeyMode       = "operator.logs.mode"
	ConfigKeyMaxSizeMB  = "operator.logs.max-size-mb"
	ConfigKeyMaxAgeDays = "operator.logs.max-age-days"
	ConfigKeyMaxBackups = "operator.logs.max-backups"
	ConfigKeyCompress   = "operator.logs.compress"

	ChannelStdout = "stdout"
	ChannelStderr = "stderr"
	ChannelFile   = "file"

	// DefaultMaxSizeMB is the maximum log file size before rotation.
	// Lumberjack always rotates by size; this cannot be disabled.
	DefaultMaxSizeMB = 100

	// DefaultMaxBackups is the number of rotated files to keep.
	// 0 means keep all rotated files (no limit).
	DefaultMaxBackups = 3

	// DefaultMaxAgeDays is the maximum age of rotated files before deletion.
	// 0 means never delete rotated files based on age.
	DefaultMaxAgeDays = 0

	FormatJSON   = "json"
	FormatLogfmt = "logfmt"

	ModeAll      = "all"
	ModeDetached = "detached"

	// EventTypeString is used as the "type" field in the JSON envelope,
	// matching the instance manager's logWrapper pattern where log messages
	// use "gadget-log". This allows consumers to distinguish data events
	// from log events in the same output stream.
	EventTypeString      = "gadget-data"
	EventTypeEmptyString = "gadget-data-empty"

	// AnnotationArrayHandling controls how TypeArray datasources are logged
	// in JSON format. Gadget authors can set this annotation on a datasource.
	// "array" (default): emit one line with "data" as a JSON array.
	// "elements": fan out into individual lines per element.
	AnnotationArrayHandling = "logs.array-handling"

	ArrayHandlingArray    = "array"
	ArrayHandlingElements = "elements"
)

var bufPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

// rotator is satisfied by lumberjack.Logger.
type rotator interface {
	Rotate() error
}

type logsOperator struct {
	enabled    bool
	channel    string
	format     string
	mode       string
	filename   string
	maxSizeMB  int
	maxAgeDays int
	maxBackups int
	compress   bool
	writer     io.Writer
	closer     io.Closer // non-nil when writer is a file (lumberjack)
	rotator    rotator   // non-nil when writer supports rotation
	sigChan    chan os.Signal
	sigStop    chan struct{} // closed to tell signal handler goroutine to exit
	sigDone    chan struct{} // closed when signal handler goroutine exits
	mu         sync.Mutex
}

type logsOperatorInstance struct {
	op         *logsOperator
	gadgetName string
	instanceID string
}

func (o *logsOperator) Name() string {
	return OperatorName
}

func (o *logsOperator) Init(globalParams *params.Params) error {
	if config.Config == nil {
		return nil
	}

	o.enabled = config.Config.GetBool(ConfigKeyEnabled)
	if !o.enabled {
		return nil
	}

	o.channel = config.Config.GetString(ConfigKeyChannel)
	if o.channel == "" {
		o.channel = ChannelStderr
	}

	o.format = config.Config.GetString(ConfigKeyFormat)
	if o.format == "" {
		o.format = FormatJSON
	}

	o.mode = config.Config.GetString(ConfigKeyMode)
	if o.mode == "" {
		o.mode = ModeAll
	}

	o.filename = config.Config.GetString(ConfigKeyFilename)
	o.maxSizeMB = config.Config.GetInt(ConfigKeyMaxSizeMB)
	o.compress = config.Config.GetBool(ConfigKeyCompress)

	o.maxAgeDays = DefaultMaxAgeDays
	if config.Config.IsSet(ConfigKeyMaxAgeDays) {
		o.maxAgeDays = config.Config.GetInt(ConfigKeyMaxAgeDays)
	}

	o.maxBackups = DefaultMaxBackups
	if config.Config.IsSet(ConfigKeyMaxBackups) {
		o.maxBackups = config.Config.GetInt(ConfigKeyMaxBackups)
	}

	return o.setup()
}

// setup validates the operator configuration and creates the writer.
// Fields must be populated before calling this method.
func (o *logsOperator) setup() error {
	switch o.channel {
	case ChannelStdout:
		o.writer = os.Stdout
	case ChannelStderr:
		o.writer = os.Stderr
	case ChannelFile:
		if o.filename == "" {
			return fmt.Errorf("operator.logs.filename must be set when channel is %q", ChannelFile)
		}
		if o.maxSizeMB < 0 {
			return fmt.Errorf("operator.logs.max-size-mb must be >= 0, got %d", o.maxSizeMB)
		}
		if o.maxAgeDays < 0 {
			return fmt.Errorf("operator.logs.max-age-days must be >= 0, got %d", o.maxAgeDays)
		}
		if o.maxBackups < 0 {
			return fmt.Errorf("operator.logs.max-backups must be >= 0, got %d", o.maxBackups)
		}

		// MaxSize: lumberjack always rotates by size (cannot be disabled).
		// 0 or unset → use our default.
		maxSizeMB := o.maxSizeMB
		if maxSizeMB <= 0 {
			maxSizeMB = DefaultMaxSizeMB
		}

		lj := &lumberjack.Logger{
			Filename:   o.filename,
			MaxSize:    maxSizeMB,
			MaxAge:     o.maxAgeDays,
			MaxBackups: o.maxBackups,
			Compress:   o.compress,
			LocalTime:  false, // use UTC for rotated file timestamps
		}
		o.writer = lj
		o.closer = lj
		o.rotator = lj
		log.Infof("logs operator: writing to file %s (max-size: %dMB, max-age: %dd, max-backups: %d)",
			o.filename, maxSizeMB, o.maxAgeDays, o.maxBackups,
		)
	default:
		return fmt.Errorf("unsupported logs channel %q; expected %q, %q, or %q", o.channel, ChannelStdout, ChannelStderr, ChannelFile)
	}

	switch o.format {
	case FormatJSON, FormatLogfmt:
	default:
		return fmt.Errorf("unsupported logs format %q; expected %q or %q", o.format, FormatJSON, FormatLogfmt)
	}

	switch o.mode {
	case ModeAll, ModeDetached:
	default:
		return fmt.Errorf("unsupported logs mode %q; expected %q or %q", o.mode, ModeAll, ModeDetached)
	}

	log.Debugf("logs operator enabled: channel=%s format=%s mode=%s", o.channel, o.format, o.mode)

	if o.rotator != nil {
		o.startSignalHandler()
	}

	return nil
}

// startSignalHandler listens for SIGHUP and triggers log rotation.
// This follows the standard convention used by nginx, syslog-ng, etc.
func (o *logsOperator) startSignalHandler() {
	o.sigChan = make(chan os.Signal, 1)
	o.sigStop = make(chan struct{})
	o.sigDone = make(chan struct{})
	signal.Notify(o.sigChan, syscall.SIGHUP)
	go func() {
		defer close(o.sigDone)
		for {
			select {
			case <-o.sigStop:
				return
			case <-o.sigChan:
				log.Infof("logs operator: received SIGHUP, rotating log file")
				o.mu.Lock()
				err := o.rotator.Rotate()
				o.mu.Unlock()
				if err != nil {
					log.Errorf("logs operator: failed to rotate log file: %v", err)
				}
			}
		}
	}()
}

func (o *logsOperator) GlobalParams() api.Params {
	return api.Params{}
}

func (o *logsOperator) InstanceParams() api.Params {
	return api.Params{}
}

func (o *logsOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	if !o.enabled {
		return nil, nil
	}

	// Only activate on the server side; on the client the CLI operator handles output.
	if !gadgetCtx.IsRemoteCall() {
		return nil, nil
	}

	// In "detached" mode, only log headless gadget instances.
	// Detached instances always have an ID set via gadgetcontext.WithID().
	if o.mode == ModeDetached && gadgetCtx.ID() == "" {
		return nil, nil
	}

	return &logsOperatorInstance{
		op:         o,
		gadgetName: gadgetCtx.ImageName(),
		instanceID: gadgetCtx.ID(),
	}, nil
}

func (o *logsOperator) Priority() int {
	return Priority
}

func (o *logsOperatorInstance) Name() string {
	return OperatorName
}

func (o *logsOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	for _, ds := range gadgetCtx.GetDataSources() {
		switch o.op.format {
		case FormatJSON:
			if err := o.subscribeJSON(gadgetCtx, ds); err != nil {
				gadgetCtx.Logger().Warnf("logs: skipping datasource %q: %v", ds.Name(), err)
			}
		case FormatLogfmt:
			if err := o.subscribeLogfmt(gadgetCtx, ds); err != nil {
				gadgetCtx.Logger().Warnf("logs: skipping datasource %q: %v", ds.Name(), err)
			}
		}
	}
	return nil
}

func (o *logsOperatorInstance) subscribeJSON(gadgetCtx operators.GadgetContext, ds datasource.DataSource) error {
	formatter, err := jsonformatter.New(ds, jsonformatter.WithShowAll(true))
	if err != nil {
		return fmt.Errorf("creating JSON formatter: %w", err)
	}

	// Pre-encode static envelope parts. These are identifier strings set at
	// operator initialization time and do not contain user-controlled content.
	dsName := ds.Name()
	gadgetName := o.gadgetName
	instanceID := o.instanceID

	writeEnvelopeCommon := func(buf *bytes.Buffer, eventType string, seq uint64) {
		buf.WriteString(`{"type":"`)
		buf.WriteString(eventType)
		buf.WriteString(`","seq":`)
		buf.WriteString(strconv.FormatUint(seq, 10))
		buf.WriteString(`,"gadget":"`)
		writeJSONSafeString(buf, gadgetName)
		buf.WriteString(`","datasource":"`)
		writeJSONSafeString(buf, dsName)
		buf.WriteByte('"')
		if instanceID != "" {
			buf.WriteString(`,"instanceID":"`)
			writeJSONSafeString(buf, instanceID)
			buf.WriteByte('"')
		}
		buf.WriteString(`,"timestamp":"`)
		buf.WriteString(time.Now().UTC().Format(time.RFC3339Nano))
		buf.WriteByte('"')
	}

	writeEnvelope := func(buf *bytes.Buffer, seq uint64) {
		writeEnvelopeCommon(buf, EventTypeString, seq)
		buf.WriteString(`,"data":`)
	}

	writeEmptyEnvelope := func(buf *bytes.Buffer, seq uint64) {
		writeEnvelopeCommon(buf, EventTypeEmptyString, seq)
	}

	emit := func(buf *bytes.Buffer) {
		buf.WriteString("}\n")

		o.op.mu.Lock()
		_, err := o.op.writer.Write(buf.Bytes())
		o.op.mu.Unlock()

		buf.Reset()
		bufPool.Put(buf)

		if err != nil {
			log.Errorf("logs operator: write error: %v", err)
		}
	}

	// fmtMu protects formatter (which reuses an internal buffer) and seq.
	var (
		fmtMu sync.Mutex
		seq   uint64
	)

	switch ds.Type() {
	case datasource.TypeArray:
		arrayHandling := ds.Annotations()[AnnotationArrayHandling]
		if arrayHandling == ArrayHandlingElements {
			ds.SubscribeArray(func(ds datasource.DataSource, dataArray datasource.DataArray) error {
				fmtMu.Lock()
				curSeq := seq
				seq++
				l := dataArray.Len()
				if l == 0 {
					fmtMu.Unlock()
					buf := bufPool.Get().(*bytes.Buffer)
					buf.Reset()
					writeEmptyEnvelope(buf, curSeq)
					emit(buf)
					return nil
				}
				for i := 0; i < l; i++ {
					buf := bufPool.Get().(*bytes.Buffer)
					buf.Reset()
					writeEnvelope(buf, curSeq)
					buf.Write(formatter.Marshal(dataArray.Get(i)))
					emit(buf)
				}
				fmtMu.Unlock()
				return nil
			}, Priority)
		} else {
			ds.SubscribeArray(func(ds datasource.DataSource, dataArray datasource.DataArray) error {
				buf := bufPool.Get().(*bytes.Buffer)
				buf.Reset()
				fmtMu.Lock()
				curSeq := seq
				seq++
				if dataArray.Len() == 0 {
					fmtMu.Unlock()
					writeEmptyEnvelope(buf, curSeq)
					emit(buf)
					return nil
				}
				writeEnvelope(buf, curSeq)
				buf.Write(formatter.MarshalArray(dataArray))
				fmtMu.Unlock()
				emit(buf)
				return nil
			}, Priority)
		}
	default:
		ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
			buf := bufPool.Get().(*bytes.Buffer)
			buf.Reset()
			fmtMu.Lock()
			curSeq := seq
			seq++
			writeEnvelope(buf, curSeq)
			buf.Write(formatter.Marshal(data))
			fmtMu.Unlock()
			emit(buf)
			return nil
		}, Priority)
	}

	return nil
}

func (o *logsOperatorInstance) subscribeLogfmt(gadgetCtx operators.GadgetContext, ds datasource.DataSource) error {
	fields := ds.Accessors(false)
	kvFuncs := make([]func(datasource.Data) (string, string), 0, len(fields))

	for _, f := range fields {
		if len(f.SubFields()) > 0 {
			continue
		}
		if f.Type() == api.Kind_Invalid ||
			datasource.FieldFlagEmpty.In(f.Flags()) ||
			datasource.FieldFlagContainer.In(f.Flags()) {
			continue
		}

		kvf, err := datasource.GetKeyValueFunc[string, string](
			f, "",
			func(v int64) string { return strconv.FormatInt(v, 10) },
			func(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) },
			func(v string) string { return v },
			func(v bool) string { return strconv.FormatBool(v) },
			func(v []byte) string { return hex.EncodeToString(v) },
		)
		if err != nil {
			continue
		}
		kvFuncs = append(kvFuncs, kvf)
	}

	dsName := ds.Name()
	gadgetName := o.gadgetName
	instanceID := o.instanceID

	writeEnvelopeCommon := func(buf *bytes.Buffer, eventType string, seq uint64) {
		buf.WriteString("type=")
		buf.WriteString(eventType)
		buf.WriteString(" seq=")
		buf.WriteString(strconv.FormatUint(seq, 10))
		buf.WriteString(" gadget=")
		logfmtWriteValue(buf, gadgetName)
		buf.WriteString(" datasource=")
		logfmtWriteValue(buf, dsName)
		if instanceID != "" {
			buf.WriteString(" instanceID=")
			logfmtWriteValue(buf, instanceID)
		}
		buf.WriteString(" timestamp=")
		buf.WriteString(time.Now().UTC().Format(time.RFC3339Nano))
	}

	writeEnvelope := func(buf *bytes.Buffer, seq uint64) {
		writeEnvelopeCommon(buf, EventTypeString, seq)
	}

	writeEmptyEnvelope := func(buf *bytes.Buffer, seq uint64) {
		writeEnvelopeCommon(buf, EventTypeEmptyString, seq)
	}

	writeFields := func(buf *bytes.Buffer, data datasource.Data) {
		for _, kvf := range kvFuncs {
			key, val := kvf(data)
			buf.WriteByte(' ')
			buf.WriteString(key)
			buf.WriteByte('=')
			logfmtWriteValue(buf, val)
		}
	}

	emit := func(buf *bytes.Buffer) {
		buf.WriteByte('\n')

		o.op.mu.Lock()
		_, err := o.op.writer.Write(buf.Bytes())
		o.op.mu.Unlock()

		buf.Reset()
		bufPool.Put(buf)

		if err != nil {
			log.Errorf("logs operator: write error: %v", err)
		}
	}

	var (
		mu  sync.Mutex
		seq uint64
	)

	switch ds.Type() {
	case datasource.TypeArray:
		ds.SubscribeArray(func(ds datasource.DataSource, dataArray datasource.DataArray) error {
			mu.Lock()
			curSeq := seq
			seq++
			l := dataArray.Len()
			if l == 0 {
				mu.Unlock()
				buf := bufPool.Get().(*bytes.Buffer)
				buf.Reset()
				writeEmptyEnvelope(buf, curSeq)
				emit(buf)
				return nil
			}
			for i := 0; i < l; i++ {
				buf := bufPool.Get().(*bytes.Buffer)
				buf.Reset()
				writeEnvelope(buf, curSeq)
				writeFields(buf, dataArray.Get(i))
				emit(buf)
			}
			mu.Unlock()
			return nil
		}, Priority)
	default:
		ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
			buf := bufPool.Get().(*bytes.Buffer)
			buf.Reset()
			mu.Lock()
			curSeq := seq
			seq++
			writeEnvelope(buf, curSeq)
			writeFields(buf, data)
			mu.Unlock()
			emit(buf)
			return nil
		}, Priority)
	}

	return nil
}

// writeJSONSafeString writes a string that is safe for embedding in a JSON
// string value. It escapes control characters, double quotes, and backslashes.
func writeJSONSafeString(buf *bytes.Buffer, s string) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			buf.WriteString(`\"`)
		case c == '\\':
			buf.WriteString(`\\`)
		case c < 0x20:
			fmt.Fprintf(buf, `\u%04x`, c)
		default:
			buf.WriteByte(c)
		}
	}
}

// logfmtWriteValue writes a logfmt-safe value. Values containing spaces, '=',
// '"', or control characters are quoted with double quotes and inner special
// characters are escaped.
func logfmtWriteValue(buf *bytes.Buffer, val string) {
	needsQuote := len(val) == 0
	if !needsQuote {
		for i := 0; i < len(val); i++ {
			c := val[i]
			if c == ' ' || c == '=' || c == '"' || c == '\n' || c == '\r' || c == '\t' || c < 0x20 {
				needsQuote = true
				break
			}
		}
	}
	if !needsQuote {
		buf.WriteString(val)
		return
	}
	buf.WriteByte('"')
	for i := 0; i < len(val); i++ {
		c := val[i]
		switch c {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if c < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, c)
			} else {
				buf.WriteByte(c)
			}
		}
	}
	buf.WriteByte('"')
}

func (o *logsOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (o *logsOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (o *logsOperatorInstance) Close(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (o *logsOperator) Close() error {
	if o.sigChan != nil {
		signal.Stop(o.sigChan)
		close(o.sigStop)
		<-o.sigDone
		o.sigChan = nil
		o.sigStop = nil
		o.sigDone = nil
	}
	if o.closer != nil {
		return o.closer.Close()
	}
	return nil
}

var Operator = &logsOperator{}

func init() {
	operators.RegisterDataOperator(Operator)
}
