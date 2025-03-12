package datasource

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

// ----- FakeData -----

// FakeData is a stub implementation of the Data interface.
type FakeData struct {
	Bytes      [][]byte
	TestResult any
}

func (fd *FakeData) private() {
}

func (fd *FakeData) payload() [][]byte {
	return fd.Bytes
}

// ----- FakeFieldAccessor -----

// FakeFieldAccessor is a stub implementation of the FieldAccessor interface.
type FakeFieldAccessor struct {
	fds *FakeDataSource
}

var _ FieldAccessor = (*FakeFieldAccessor)(nil)

func (ffa *FakeFieldAccessor) Name() string {
	// TODO: implement
	return ""
}

func (ffa *FakeFieldAccessor) FullName() string {
	// TODO: implement
	return ""
}

func (ffa *FakeFieldAccessor) Size() uint32 {
	// TODO: implement
	return 0
}

func (ffa *FakeFieldAccessor) Get(data Data) []byte {

	return data.payload()[0]
}

func (ffa *FakeFieldAccessor) Set(data Data, value []byte) error {

	return errors.New("not implemented")
}

func (ffa *FakeFieldAccessor) IsRequested() bool {
	// TODO: implement
	return false
}

func (ffa *FakeFieldAccessor) AddSubField(name string, kind api.Kind, opts ...FieldOption) (FieldAccessor, error) {
	// TODO: implement
	return nil, errors.New("not implemented")
}

func (ffa *FakeFieldAccessor) GetSubFieldsWithTag(tag ...string) []FieldAccessor {
	// TODO: implement
	return nil
}

func (ffa *FakeFieldAccessor) Parent() FieldAccessor {
	// TODO: implement
	return nil
}

func (ffa *FakeFieldAccessor) SubFields() []FieldAccessor {
	// TODO: implement
	return nil
}

func (ffa *FakeFieldAccessor) SetHidden(hidden bool, recurse bool) {
	// TODO: implement
}

func (ffa *FakeFieldAccessor) Type() api.Kind {
	// TODO: implement
	return 0
}

func (ffa *FakeFieldAccessor) Flags() uint32 {
	// TODO: implement
	return 0
}

func (ffa *FakeFieldAccessor) Tags() []string {
	// TODO: implement
	return nil
}

func (ffa *FakeFieldAccessor) AddTags(tags ...string) {
	// TODO: implement
}

func (ffa *FakeFieldAccessor) HasAllTagsOf(tags ...string) bool {
	// TODO: implement
	return false
}

func (ffa *FakeFieldAccessor) HasAnyTagsOf(tags ...string) bool {
	// TODO: implement
	return false
}

func (ffa *FakeFieldAccessor) Annotations() map[string]string {
	// TODO: implement
	return nil
}

func (ffa *FakeFieldAccessor) AddAnnotation(key, value string) {
	// TODO: implement
}

func (ffa *FakeFieldAccessor) RemoveReference(recurse bool) {
	// TODO: implement
}

func (ffa *FakeFieldAccessor) Rename(newName string) error {
	// TODO: implement
	return errors.New("not implemented")
}

func (ffa *FakeFieldAccessor) Uint8(data Data) (uint8, error) {
	// TODO: implement
	return 0, nil
}

func (ffa *FakeFieldAccessor) Uint16(data Data) (uint16, error) {
	// TODO: implement
	return 0, nil
}

func (ffa *FakeFieldAccessor) Uint32(data Data) (uint32, error) {
	// TODO: implement
	return 0, nil
}

func (ffa *FakeFieldAccessor) Uint64(data Data) (uint64, error) {
	// TODO: implement
	return 0, nil
}

func (ffa *FakeFieldAccessor) Int8(data Data) (int8, error) {
	// TODO: implement
	return 0, nil
}

func (ffa *FakeFieldAccessor) Int16(data Data) (int16, error) {
	// TODO: implement
	return 0, nil
}

func (ffa *FakeFieldAccessor) Int32(data Data) (int32, error) {
	// TODO: implement
	return 0, nil
}

func (ffa *FakeFieldAccessor) Int64(data Data) (int64, error) {
	// TODO: implement
	return 0, nil
}

func (ffa *FakeFieldAccessor) Float32(data Data) (float32, error) {
	// TODO: implement
	return 0, nil
}

func (ffa *FakeFieldAccessor) Float64(data Data) (float64, error) {
	// TODO: implement
	return 0, nil
}

func (ffa *FakeFieldAccessor) String(data Data) (string, error) {
	// TODO: implement
	return "", nil
}

func (ffa *FakeFieldAccessor) Bytes(data Data) ([]byte, error) {
	// TODO: implement
	return nil, nil
}

func (ffa *FakeFieldAccessor) Bool(data Data) (bool, error) {
	// TODO: implement
	return false, nil
}

func (ffa *FakeFieldAccessor) Uint8Array(data Data) ([]uint8, error) {
	// TODO: implement
	return nil, nil
}

func (ffa *FakeFieldAccessor) Uint16Array(data Data) ([]uint16, error) {
	// TODO: implement
	return nil, nil
}

func (ffa *FakeFieldAccessor) Uint32Array(data Data) ([]uint32, error) {
	// TODO: implement
	return nil, nil
}

func (ffa *FakeFieldAccessor) Uint64Array(data Data) ([]uint64, error) {
	// TODO: implement
	return nil, nil
}

func (ffa *FakeFieldAccessor) Int8Array(data Data) ([]int8, error) {
	// TODO: implement
	return nil, nil
}

func (ffa *FakeFieldAccessor) Int16Array(data Data) ([]int16, error) {
	// TODO: implement
	return nil, nil
}

func (ffa *FakeFieldAccessor) Int32Array(data Data) ([]int32, error) {
	// TODO: implement
	return nil, nil
}

func (ffa *FakeFieldAccessor) Int64Array(data Data) ([]int64, error) {
	// TODO: implement
	return nil, nil
}

func (ffa *FakeFieldAccessor) Float32Array(data Data) ([]float32, error) {
	// TODO: implement
	return nil, nil
}

func (ffa *FakeFieldAccessor) Float64Array(data Data) ([]float64, error) {
	// TODO: implement
	return nil, nil
}

func (ffa *FakeFieldAccessor) PutUint8(data Data, val uint8) error {
	// TODO: implement
	return errors.New("not implemented")
}

func (ffa *FakeFieldAccessor) PutUint16(data Data, val uint16) error {
	// TODO: implement
	return errors.New("not implemented")
}

func (ffa *FakeFieldAccessor) PutUint32(data Data, val uint32) error {
	// TODO: implement
	return errors.New("not implemented")
}

func (ffa *FakeFieldAccessor) PutUint64(data Data, val uint64) error {
	b := ffa.Get(data)
	if len(b) != 8 {
		return invalidFieldLengthErr(len(b), 8)
	}
	ffa.fds.byteOrder.PutUint64(ffa.Get(data), val)
	return nil
}

func (ffa *FakeFieldAccessor) PutInt8(data Data, val int8) error {
	// TODO: implement
	return errors.New("not implemented")
}

func (ffa *FakeFieldAccessor) PutInt16(data Data, val int16) error {
	// TODO: implement
	return errors.New("not implemented")
}

func (ffa *FakeFieldAccessor) PutInt32(data Data, val int32) error {
	// TODO: implement
	return errors.New("not implemented")
}

func (ffa *FakeFieldAccessor) PutInt64(data Data, val int64) error {
	// TODO: implement
	return errors.New("not implemented")
}

func (ffa *FakeFieldAccessor) PutFloat32(data Data, val float32) error {
	// TODO: implement
	return errors.New("not implemented")
}

func (ffa *FakeFieldAccessor) PutFloat64(data Data, val float64) error {
	// TODO: implement
	return errors.New("not implemented")
}

func (ffa *FakeFieldAccessor) PutString(data Data, val string) error {
	// TODO: implement
	return errors.New("not implemented")
}

func (ffa *FakeFieldAccessor) PutBytes(data Data, val []byte) error {
	// TODO: implement
	return errors.New("not implemented")
}

func (ffa *FakeFieldAccessor) PutBool(data Data, val bool) error {
	// TODO: implement
	return errors.New("not implemented")
}

// ----- FakeDataSource -----

// FakeDataSource is a stub implementation of the DataSource interface.
type FakeDataSource struct {
	annotations  map[string]string
	fields       map[FieldAccessor](map[string]any)
	byteOrder    binary.ByteOrder
	payloadCount int
}

var _ DataSource = (*FakeDataSource)(nil)

func NewFakeDataSource() *FakeDataSource {
	return &FakeDataSource{
		annotations: make(map[string]string),
		fields:      make(map[FieldAccessor](map[string]any)),
		byteOrder:   binary.LittleEndian,
	}
}

func (fds *FakeDataSource) Name() string {
	// TODO: implement
	return ""
}

func (fds *FakeDataSource) Type() Type {
	// TODO: implement
	return 0
}

func (fds *FakeDataSource) AddStaticFields(totalSize uint32, fields []StaticField) (FieldAccessor, error) {
	// TODO: implement
	return nil, errors.New("not implemented")
}

func (fds *FakeDataSource) AddField(fieldName string, kind api.Kind, options ...FieldOption) (FieldAccessor, error) {
	// TODO: implement
	ffa := &FakeFieldAccessor{}
	fieldsInfo := make(map[string]any)
	fieldsInfo["fieldName"] = fieldName
	fieldsInfo["kind"] = kind
	fieldsInfo["options"] = options

	fds.fields[ffa] = fieldsInfo

	return ffa, nil
}

func (fds *FakeDataSource) NewPacketSingle() (PacketSingle, error) {
	// TODO: implement
	return nil, errors.New("not implemented")
}

func (fds *FakeDataSource) NewPacketSingleFromRaw(b []byte) (PacketSingle, error) {
	// TODO: implement
	return nil, errors.New("not implemented")
}

func (fds *FakeDataSource) NewPacketArray() (PacketArray, error) {
	// TODO: implement
	return nil, errors.New("not implemented")
}

func (fds *FakeDataSource) NewPacketArrayFromRaw(b []byte) (PacketArray, error) {
	// TODO: implement
	return nil, errors.New("not implemented")
}

func (fds *FakeDataSource) GetField(fieldName string) FieldAccessor {
	// TODO: implement
	return nil
}

func (fds *FakeDataSource) GetFieldsWithTag(tag ...string) []FieldAccessor {
	// TODO: implement
	return nil
}

func (fds *FakeDataSource) EmitAndRelease(p Packet) error {
	// TODO: implement
	return errors.New("not implemented")
}

func (fds *FakeDataSource) Release(p Packet) {
	// TODO: implement
}

func (fds *FakeDataSource) ReportLostData(lostSampleCount uint64) {
	// TODO: implement
}

func (fds *FakeDataSource) Dump(p Packet, w io.Writer) {
	// TODO: implement
}

func (fds *FakeDataSource) Subscribe(dataFn DataFunc, priority int) error {
	// TODO: implement
	return errors.New("not implemented")
}

func (fds *FakeDataSource) SubscribeArray(dataFn ArrayFunc, priority int) error {
	// TODO: implement
	return errors.New("not implemented")
}

func (fds *FakeDataSource) SubscribePacket(packetFn PacketFunc, priority int) error {
	// TODO: implement
	return errors.New("not implemented")
}

func (fds *FakeDataSource) Parser() (parser.Parser, error) {
	// TODO: implement
	return nil, errors.New("not implemented")
}

func (fds *FakeDataSource) Fields() []*api.Field {
	// TODO: implement
	return nil
}

func (fds *FakeDataSource) Accessors(rootOnly bool) []FieldAccessor {
	// TODO: implement
	return nil
}

func (fds *FakeDataSource) Unreference() {
	// TODO: implement
}

func (fds *FakeDataSource) IsReferenced() bool {
	// TODO: implement
	return false
}

func (fds *FakeDataSource) ByteOrder() binary.ByteOrder {
	// TODO: implement
	return fds.byteOrder
}

func (fds *FakeDataSource) AddAnnotation(key, value string) {
	// TODO: implement
}

func (fds *FakeDataSource) AddTags(tags ...string) {
	// TODO: implement
}

func (fds *FakeDataSource) Annotations() map[string]string {
	// TODO: implement
	return fds.annotations
}

func (fds *FakeDataSource) Tags() []string {
	// TODO: implement
	return nil
}

func (fds *FakeDataSource) CopyFieldsTo(ds DataSource) error {
	// TODO: implement
	return errors.New("not implemented")
}

// FakeLogger is a stub implementation of logger.Logger for testing purposes.
type FakeLogger struct {
	level logger.Level
}

func (fl *FakeLogger) Panic(params ...any) {
	// TODO: Implement Fake Panic Logging
}

func (fl *FakeLogger) Panicf(fmt string, params ...any) {
	// TODO: Implement Fake Panic Logging with format
}

func (fl *FakeLogger) Fatal(params ...any) {
	// TODO: Implement Fake Fatal Logging
}

func (fl *FakeLogger) Fatalf(fmt string, params ...any) {
	// TODO: Implement Fake Fatal Logging with format
}

func (fl *FakeLogger) Error(params ...any) {
	// TODO: Implement Fake Error Logging
}

func (fl *FakeLogger) Errorf(fmt string, params ...any) {
	// TODO: Implement Fake Error Logging with format
}

func (fl *FakeLogger) Warn(params ...any) {
	// TODO: Implement Fake Warning Logging
}

func (fl *FakeLogger) Warnf(fmt string, params ...any) {
	// TODO: Implement Fake Warning Logging with format
}

func (fl *FakeLogger) Info(params ...any) {
	// TODO: Implement Fake Info Logging
}

func (fl *FakeLogger) Infof(fmt string, params ...any) {
	// TODO: Implement Fake Info Logging with format
}

func (fl *FakeLogger) Debug(params ...any) {
	// TODO: Implement Fake Debug Logging
}

func (fl *FakeLogger) Debugf(fmt string, params ...any) {
	// TODO: Implement Fake Debug Logging with format
}

func (fl *FakeLogger) Trace(params ...any) {
	// TODO: Implement Fake Trace Logging
}

func (fl *FakeLogger) Tracef(fmt string, params ...any) {
	// TODO: Implement Fake Trace Logging with format
}

func (fl *FakeLogger) Log(severity logger.Level, params ...any) {
	// TODO: Implement Fake Generic Log
}

func (fl *FakeLogger) Logf(severity logger.Level, format string, params ...any) {
	// TODO: Implement Fake Generic Log with format
}

func (fl *FakeLogger) SetLevel(level logger.Level) {
	fl.level = level
}

func (fl *FakeLogger) GetLevel() logger.Level {
	return fl.level
}
