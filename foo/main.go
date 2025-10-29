package main

import (
	"fmt"
	"log"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// generateGoTypeDefinition creates a Go struct definition from a protobuf message descriptor
func generateGoTypeDefinition(msgDesc protoreflect.MessageDescriptor) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("type %s struct {\n", msgDesc.Name()))

	for i := 0; i < msgDesc.Fields().Len(); i++ {
		field := msgDesc.Fields().Get(i)
		fieldName := string(field.Name())
		if len(fieldName) > 0 {
			fieldName = strings.ToUpper(fieldName[:1]) + fieldName[1:] // Capitalize first letter
		}
		goType := protoTypeToGoType(field)

		sb.WriteString(fmt.Sprintf("\t%s %s `json:\"%s\"`\n", fieldName, goType, field.Name()))
	}

	sb.WriteString("}")
	return sb.String()
}

// protoTypeToGoType converts protobuf field types to Go types
func protoTypeToGoType(field protoreflect.FieldDescriptor) string {
	var baseType string

	switch field.Kind() {
	case protoreflect.Int32Kind:
		baseType = "int32"
	case protoreflect.Int64Kind:
		baseType = "int64"
	case protoreflect.StringKind:
		baseType = "string"
	case protoreflect.BoolKind:
		baseType = "bool"
	case protoreflect.FloatKind:
		baseType = "float32"
	case protoreflect.DoubleKind:
		baseType = "float64"
	case protoreflect.BytesKind:
		baseType = "[]byte"
	default:
		baseType = "interface{}" // fallback for unknown types
	}

	if field.Cardinality() == protoreflect.Repeated {
		return "[]" + baseType
	}

	return baseType
}

func main() {
	// Step 1: Define a message structure dynamically
	msgDescProto := &descriptorpb.DescriptorProto{
		Name: proto.String("MyMessage"),
		Field: []*descriptorpb.FieldDescriptorProto{
			{
				Name:   proto.String("id"),
				Number: proto.Int32(1),
				Type:   descriptorpb.FieldDescriptorProto_TYPE_INT32.Enum(),
			},
			{
				Name:   proto.String("name"),
				Number: proto.Int32(2),
				Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
			},
			{
				Name:   proto.String("foo"),
				Number: proto.Int32(3),
				Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
				Label:  descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum(),
			},
		},
	}

	// Step 2: Wrap it in a FileDescriptorProto
	fileDescProto := &descriptorpb.FileDescriptorProto{
		Name:        proto.String("my.proto"),
		Package:     proto.String("example"),
		MessageType: []*descriptorpb.DescriptorProto{msgDescProto},
	}

	// Step 3: Build a FileDescriptor
	fd, err := protodesc.NewFile(fileDescProto, nil)
	if err != nil {
		log.Fatalf("failed to create FileDescriptor: %v", err)
	}

	// Step 4: Get the message descriptor and create a dynamic message
	msgDesc := fd.Messages().ByName("MyMessage")
	msg := dynamicpb.NewMessage(msgDesc)

	// Print the Go type definition
	fmt.Printf("Go Type Definition:\n%s\n\n", generateGoTypeDefinition(msgDesc))

	// Step 5: Set fields dynamically
	msg.Set(msgDesc.Fields().ByName("id"), protoreflect.ValueOfInt32(42))
	msg.Set(msgDesc.Fields().ByName("name"), protoreflect.ValueOfString("Harry"))

	// Set the foo string array
	fooField := msgDesc.Fields().ByName("foo")
	fooList := msg.Mutable(fooField).List()
	fooList.Append(protoreflect.ValueOfString("one"))
	fooList.Append(protoreflect.ValueOfString("two"))
	fooList.Append(protoreflect.ValueOfString("three"))

	// Step 6: Serialize to binary
	binData, err := proto.Marshal(msg)
	if err != nil {
		log.Fatalf("failed to marshal: %v", err)
	}
	fmt.Printf("Binary: %x\n", binData)

	// Step 7: Serialize to JSON
	jsonData, err := protojson.MarshalOptions{
		Indent:          "  ",
		UseProtoNames:   true, // use field names from proto, not lowerCamel
		EmitUnpopulated: true, // include zero values
	}.Marshal(msg)
	if err != nil {
		log.Fatalf("failed to marshal to JSON: %v", err)
	}
	fmt.Printf("JSON:\n%s\n", jsonData)

	// Step 8: Deserialize back from JSON
	newMsg := dynamicpb.NewMessage(msgDesc)
	if err := protojson.Unmarshal(jsonData, newMsg); err != nil {
		log.Fatalf("failed to unmarshal JSON: %v", err)
	}
	fmt.Printf("Decoded message:\n%s\n", newMsg)
}
