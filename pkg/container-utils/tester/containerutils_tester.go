package main

import (
	"flag"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	containerutils "github.com/kinvolk/inspektor-gadget/pkg/container-utils"
	"github.com/kinvolk/inspektor-gadget/pkg/container-utils/containerd"
	"github.com/kinvolk/inspektor-gadget/pkg/container-utils/crio"
	"github.com/kinvolk/inspektor-gadget/pkg/container-utils/docker"
	runtimeclient "github.com/kinvolk/inspektor-gadget/pkg/container-utils/runtime-client"
	"golang.org/x/exp/constraints"
)

// Main function for containerutils tester.
func main() {

	baseName := path.Base(os.Args[0])
	runtimes := map[string]struct{
		name string
		socketPath string
	}{
		"containerd": { containerd.Name, containerd.DefaultSocketPath },
		"crio":  { crio.Name, crio.DefaultSocketPath },
		"docker":  { docker.Name, docker.DefaultSocketPath },
	}
	commands := map[string]func(runtimeClient runtimeclient.ContainerRuntimeClient, args []string) error {
		"list": listCmd,
		"get": getCmd,
		"get-pid": getPidCmd,
		"get-extended": getExtendedCmd,
	}

	// Setup flags.
	flagSet := flag.NewFlagSet(baseName, flag.ContinueOnError)
	socketPathFlag := flagSet.String("s", "", "Override socket path for runtime")
    helpFlag := flagSet.Bool("h", false, "Show this help")

	// Show syntax function.
	showSyntax := func() {
		fmt.Println("Container-utils Tester")
		fmt.Printf("Syntax: %s <%s> <%s> [options] [container-id]\n", baseName, 
				   joinMapKeys(runtimes, "/"), joinMapKeys(commands, "/"))
		fmt.Println("Options:")
		flagSet.PrintDefaults()
		os.Exit(0)
	}

	// Verify number of arguments.
	if len(os.Args) < 3 {
		showSyntax()
	}

	// Parse command line options (without executable, runtime and command).
	flagSet.Parse(os.Args[3:])

	// Check if syntax needs to be shown.
	if helpFlag != nil && *helpFlag {
		showSyntax()
	}

	// Verify runtime is valid.
	runtimeName, ok := runtimes[os.Args[1]]
	if !ok {
		fmt.Println("Runtime is invalid, available runtimes:", joinMapKeys(runtimes, ", "))
		os.Exit(1)
	}

	// Verify command is valid.
	cmd := os.Args[2]
	cmdFunc, ok := commands[cmd]
	if !ok {
		fmt.Println("Command is invalid, available commands:", joinMapKeys(commands, ", "))
		os.Exit(1)
	}

	// Create the runtime client.
	runtimeConfig := containerutils.RuntimeConfig {
		Name: runtimeName.name,
		SocketPath: runtimeName.name,
	}
	if socketPathFlag != nil {
		runtimeConfig.SocketPath = *socketPathFlag
	}
	runtimeClient, err := containerutils.NewContainerRuntimeClient(&runtimeConfig)
	if err != nil {
		fmt.Println("Error creating runtime:", err.Error())
		os.Exit(1)
	}

	// Run the command.
	err = cmdFunc(runtimeClient, flagSet.Args())
	runtimeClient.Close()
	if err != nil {
		fmt.Println("Error running", cmd, "command:", err.Error())
		os.Exit(1)
	}
}

// Command function for list command.
func listCmd(runtimeClient runtimeclient.ContainerRuntimeClient, args []string) error {

	// Get list of containers.
	containers, err := runtimeClient.GetContainers()
	if err != nil {
		return err
	}

	// Set the columns.
	columns := []string { "ID", "Name", "Running", "Runtime"}

	// Turn containers to table.
	table := make([][]string, len(containers))
	for i, container := range containers {
		row := []string { container.ID, container.Name, strconv.FormatBool(container.Running), container.Runtime }
		table[i] = append(table[i], row...)
	}

	// Print the table.
	printTable(columns, table)

	return nil
}

// Command function for get command.
func getCmd(runtimeClient runtimeclient.ContainerRuntimeClient, args []string) error {

	// Get the container ID argument.
	if len(args) < 1 {
		return fmt.Errorf("missing container ID argument")
	}

	// Get container by ID.
	container, err := runtimeClient.GetContainer(args[0])
	if err != nil {
		return err
	}

	// Set the columns.
	columns := []string { "ID", "Name", "Running", "Runtime"}

	// Turn containers to table.
	row := []string { container.ID, container.Name, strconv.FormatBool(container.Running), container.Runtime }
	table := [][]string{ row }

	// Print the table.
	printTable(columns, table)

	return nil
}

// Command function for get-extended command.
func getExtendedCmd(runtimeClient runtimeclient.ContainerRuntimeClient, args []string) error {

	// Get the container ID argument.
	if len(args) < 1 {
		return fmt.Errorf("missing container ID argument")
	}

	// Get container extended information by ID.
	container, err := runtimeClient.GetContainerExtended(args[0])
	if err != nil {
		return err
	}

	// Set the columns.
	columns := []string { "ID", "Name", "Running", "Runtime", "Pid", "State", "CgroupsPath" }

	// Turn containers to table.
	row := []string { container.ID, container.Name, strconv.FormatBool(container.Running), container.Runtime,
					  strconv.Itoa(container.Pid), container.State, container.CgroupsPath }
	
	table := [][]string{ row }

	// Print the table.
	printTable(columns, table)
	fmt.Println()

	// Set the columns for mounts.
	columns = []string { "Source", "Destination" }

	// Turn containers to table.
	table = make([][]string, len(container.Mounts))
	for i, mount := range container.Mounts {
		row := []string { mount.Source, mount.Destination }
		table[i] = append(table[i], row...)
	}

	// Print the mounts table.
	printTable(columns, table)

	return nil
}

// Command function for get PID command.
func getPidCmd(runtimeClient runtimeclient.ContainerRuntimeClient, args []string) error {

	// Get the container ID argument.
	if len(args) < 1 {
		return fmt.Errorf("missing container ID argument")
	}

	// Get container PID by ID.
	pid, err := runtimeClient.PidFromContainerID(args[0])
	if err != nil {
		return err
	}

	// Set the columns.
	columns := []string { "ID", "PID"}

	// Turn containers to table.
	row := []string { args[0], strconv.Itoa(pid) }
	table := [][]string{ row }

	// Print the table.
	printTable(columns, table)

	return nil
}

// Helper function for joining keys of string maps.
func joinMapKeys[T any](elemMap map[string]T, sep string) string {
	elems := []string{}
	for k := range elemMap {
		elems = append(elems, k)
	}
	return strings.Join(elems, sep)
}

// Helper function for printing tables.
func printTable(columns []string, table [][]string) {

	// Find width of all columns.
	columnWidths := make([]int, len(columns))
	for i, columnString := range columns {
		columnWidths[i] = max(columnWidths[i], len(columnString))
	}
	for _, row := range table {
		for i, cellString := range row {
			for i >= len(columnWidths) {
				columnWidths = append(columnWidths, 0)
			}
			columnWidths[i] = max(columnWidths[i], len(cellString))
		}
	}

	// Print the table header
	for i, columnString := range columns {
		cellFmt := "%-" + strconv.Itoa(columnWidths[i] + 1) + "s"
		fmt.Printf(cellFmt, columnString)
	}

	// Print the separator.
	fmt.Println()
	for i := range columnWidths {
		cellFmt := "%-" + strconv.Itoa(columnWidths[i] + 1) + "s"
		fmt.Printf(cellFmt, strings.Repeat("-", columnWidths[i]))
	}

	// Print table contents.
	fmt.Println()
	for _, row := range table {
		for i, cellString := range row {
			cellFmt := "%-" + strconv.Itoa(columnWidths[i] + 1) + "s"
			fmt.Printf(cellFmt, cellString)
		}
		fmt.Println()
	}
}

func max[T constraints.Ordered](a, b T) T {
	if a > b {
		return a
	}
	return b
}