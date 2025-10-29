package main

import (
	"fmt"
	"os"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func do() error {
	ds, err := datasource.New(datasource.TypeSingle, "example_events")
	if err != nil {
		return fmt.Errorf("failed to create data source: %w", err)
	}

	parent, err := ds.AddField("parent", api.ArrayOf(api.Kind_Invalid))
	if err != nil {
		return fmt.Errorf("failed to add parent field: %w", err)
	}

	nameField, err := parent.AddSubField("name", api.Kind_String)
	if err != nil {
		return fmt.Errorf("failed to add name field: %w", err)
	}

	// Step 2: Add a string array field
	tagsField, err := parent.AddSubField("tags", api.Kind_String)
	if err != nil {
		return fmt.Errorf("failed to add tags field: %w", err)
	}

	// subscribe
	// Create JSON formatter
	jsonFormatter, err := igjson.New(ds,
		// Show all fields
		igjson.WithShowAll(true),
		// Print JSON in a pretty format with 2-space indentation
		igjson.WithPretty(true, "  "),
	)
	if err != nil {
		return fmt.Errorf("failed to create JSON formatter: %w", err)
	}

	// Subscribe to the data source
	ds.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
		jsonOutput := jsonFormatter.Marshal(data)
		fmt.Println(string(jsonOutput))
		//fmt.Printf("\n📋 Received event as JSON:\n%s\n", jsonOutput)
		return nil
	}, 100)

	// Create and emit
	data, err := ds.NewPacketSingle()
	if err != nil {
		return fmt.Errorf("failed to create packet: %w", err)
	}

	err = parent.Set(data, []byte("foobaryes")) // Initialize parent field
	if err != nil {
		return fmt.Errorf("failed to set parent field: %w", err)
	}

	// Set the name field
	err = nameField.PutString(data, "foo")
	if err != nil {
		return fmt.Errorf("failed to set name field: %w", err)
	}
	err = tagsField.PutStringArray(data, []string{"tag1", "tag2", "tag3"})
	if err != nil {
		return fmt.Errorf("failed to set name field: %w", err)
	}

	// Emit the data
	ds.EmitAndRelease(data)

	return nil
}

func main() {
	if err := do(); err != nil {
		fmt.Printf("❌ Error running application: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("\n🎉 Example completed successfully!")
}
