// Copyright 2019-2022 The Inspektor Gadget authors
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

package trace

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	commontrace "github.com/inspektor-gadget/inspektor-gadget/cmd/common/trace"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcpdump/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Decoder string

type nameEvent struct {
	IP   net.IP
	Name string
}

type TCPDumpParser struct {
	commonutils.BaseParser[types.Event]
	pcapngWriter   *pcapgo.NgWriter
	writer         io.Writer
	decoder        Decoder
	snapLen        int
	filter         string
	interfaces     map[string]int
	interfacesLock sync.RWMutex
	events         chan *types.Event // channel for incoming packets
	nameEvents     chan *nameEvent   // channel for dns resolution information
}

const (
	DecoderWireshark = "wireshark"
	DecoderTCPDump   = "tcpdump"
	DecoderExternal  = "external"
	DecoderInternal  = "internal"
	DecoderFile      = "file"
)

var decoderCmd *exec.Cmd

// populate DNS entries
func (p *TCPDumpParser) populateDNS(ctx context.Context) ([]byte, error) {
	client, err := k8sutil.NewClientsetFromConfigFlags(utils.KubernetesConfigFlags)
	if err != nil {
		return nil, err
	}

	go func() {
		list, _ := client.CoreV1().Pods("").Watch(ctx, metav1.ListOptions{})
		for info := range list.ResultChan() {
			pod := info.Object.(*corev1.Pod)
			for _, ip := range pod.Status.PodIPs {
				if parsedIP := net.ParseIP(ip.IP); parsedIP != nil {
					p.nameEvents <- &nameEvent{
						IP:   parsedIP,
						Name: fmt.Sprintf("%s.%s.pod", strings.Replace(ip.IP, ".", "-", -1), pod.Namespace),
					}
				}
			}
		}
	}()
	go func() {
		list, _ := client.CoreV1().Services("").Watch(ctx, metav1.ListOptions{})
		for info := range list.ResultChan() {
			svc := info.Object.(*corev1.Service)
			for _, ip := range svc.Spec.ClusterIPs {
				if parsedIP := net.ParseIP(ip); parsedIP != nil {
					p.nameEvents <- &nameEvent{
						IP:   parsedIP,
						Name: fmt.Sprintf("%s.%s.svc", svc.Name, svc.Namespace),
					}
				}
			}
			for _, ip := range svc.Spec.ExternalIPs {
				if parsedIP := net.ParseIP(ip); parsedIP != nil {
					p.nameEvents <- &nameEvent{
						IP:   parsedIP,
						Name: fmt.Sprintf("%s.%s.svc", svc.Name, svc.Namespace),
					}
				}
			}
			if svc.Spec.LoadBalancerIP != "" {
				if parsedIP := net.ParseIP(svc.Spec.LoadBalancerIP); parsedIP != nil {
					p.nameEvents <- &nameEvent{
						IP:   parsedIP,
						Name: fmt.Sprintf("%s.%s.svc", svc.Name, svc.Namespace),
					}
				}
			}
		}
	}()
	return nil, nil
}

func getDNSBlock(ip net.IP, name string) []byte {
	// TODO: add support for IPv6
	ipv4 := ip.To4()
	if ipv4 == nil || len(ipv4) != net.IPv4len {
		return nil
	}

	nsblock := bytes.NewBuffer(nil)

	header := make([]byte, 8)
	binary.LittleEndian.PutUint32(header[0:], 0x00000004) // Block type
	nsblock.Write(header)

	plen := 4 + 4 + len([]byte(name)) + 1 // header + ip + name + \0 terminator
	if plen%4 != 0 {
		// pad to 32bit
		plen += 4 - plen%4
	}
	record := make([]byte, plen)

	binary.LittleEndian.PutUint16(record[0:2], 0x0001)                        // ipv4
	binary.LittleEndian.PutUint16(record[2:4], uint16(4+len([]byte(name))+1)) // length of name + \0 terminator

	copy(record[4:8], ipv4[0:4])
	copy(record[8:], []byte(name))
	nsblock.Write(record)

	footer := make([]byte, 4)
	nsblock.Write(footer) // nrb_record_end + length

	nsblock.Write(footer) // Block size

	out := nsblock.Bytes()
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	binary.LittleEndian.PutUint32(out[len(out)-4:], uint32(len(out)))
	return out
}

func newTCPDumpCmd() *cobra.Command {
	commonFlags := &utils.CommonFlags{
		OutputConfig: commonutils.OutputConfig{
			OutputMode:    commonutils.OutputModeCustom,
			CustomColumns: []string{},
		},
	}

	var decoderParam string
	var decoderArgsParam string
	var decoderBinaryParam string
	var snapLen int
	var filenameParam string
	var disableDNSPopulation bool

	cmd := &cobra.Command{
		Use:   "tcpdump",
		Short: "Trace packets",
		RunE: func(cmd *cobra.Command, args []string) error {
			decoderArgs := []string{}
			var decoder Decoder
			var decoderBinary string
			var ngw *pcapgo.NgWriter

			// Writer, used for external output (pcapng)
			var out io.Writer

			switch Decoder(decoderParam) {
			case DecoderWireshark:
				decoder = DecoderExternal
				decoderArgs = []string{"-k", "-i", "-"}
				decoderBinary = "wireshark"
			case DecoderTCPDump:
				decoder = DecoderExternal
				decoderArgs = []string{"-r", "-"}
				decoderBinary = "tcpdump"
			case DecoderInternal:
				decoder = DecoderInternal
			case DecoderFile:
				decoder = DecoderFile
			default:
				return errors.New("unknown decoder")
			}

			if decoder == DecoderFile {
				if filenameParam == "" {
					return fmt.Errorf("no filename specified")
				}
				f, err := os.Create(filenameParam)
				if err != nil {
					return fmt.Errorf("creating file: %w", err)
				}
				out = f
			}

			if decoder == DecoderExternal {
				r, w, err := os.Pipe()
				if err != nil {
					return fmt.Errorf("could not create pipe: %w", err)
				}

				if decoderArgsParam != "" {
					decoderArgs = append(decoderArgs, strings.Split(decoderArgsParam, " ")...)
				}
				if decoderBinaryParam != "" {
					decoderBinary = decoderBinaryParam
				}

				// xwr := &wr{File: os.Stdout}

				decoderCmd = exec.Command(decoderBinary, decoderArgs...)
				decoderCmd.Stdout = os.Stdout
				decoderCmd.Stderr = os.Stderr
				decoderCmd.Stdin = r
				err = decoderCmd.Start()
				if err != nil {
					return fmt.Errorf("could not start tcpdump: %w", err)
				}

				out = w
			}

			if out != nil {
				var err error
				dummyInterface := pcapgo.DefaultNgInterface
				dummyInterface.LinkType = layers.LinkTypeEthernet
				dummyInterface.SnapLength = uint32(snapLen)
				ngw, err = pcapgo.NewNgWriterInterface(out, dummyInterface, pcapgo.NgWriterOptions{SectionInfo: pcapgo.NgSectionInfo{
					Hardware:    runtime.GOARCH,
					OS:          runtime.GOOS,
					Application: "InspektorGadget",
					Comment:     "using gopacket",
				}})
				if err != nil {
					return fmt.Errorf("instantiating NgWriter: %w", err)
				}
				ngw.Flush()
			}

			filter := strings.Join(args, " ")

			tcpdumpGadget := &TraceGadget[types.Event]{
				name:        "tcpdump",
				commonFlags: commonFlags,
				parser:      NewTCPDump(&commonFlags.OutputConfig, filter, snapLen, decoder, ngw, out),
				params: map[string]string{
					types.FilterStringParam: filter,
					types.SnapLenParam:      strconv.Itoa(snapLen),
				},
			}

			return tcpdumpGadget.Run()
		},
	}

	utils.AddCommonFlags(cmd, commonFlags)
	cmd.Flags().StringVar(&decoderParam, "decoder", "internal", "name of the decoder to use (either tcpdump, wireshark, internal or file)")
	cmd.Flags().StringVar(&decoderArgsParam, "decoder-args", "", "arguments to forward to decoder")
	cmd.Flags().StringVar(&decoderBinaryParam, "decoder-binary", "", "path to decoder binary (defaults to 'wireshark' or 'tcpdump' depending on decoder)")
	cmd.Flags().StringVar(&filenameParam, "out-file", "", "output file name")
	cmd.Flags().BoolVar(&disableDNSPopulation, "disable-dns", false, "disable DNS population from kubernetes")
	cmd.Flags().IntVar(&snapLen, "snaplen", 68, "number of bytes to capture per packet")
	return cmd
}

func NewTCPDump(outputConfig *commonutils.OutputConfig, filter string, snapLen int, decoder Decoder, pcapngWriter *pcapgo.NgWriter, writer io.Writer) commontrace.TraceParser[types.Event] {
	columnsWidth := map[string]int{}
	outputConfig.OutputMode = commonutils.OutputModeCustom
	p := &TCPDumpParser{
		BaseParser:   commonutils.NewBaseWidthParser[types.Event](columnsWidth, outputConfig),
		filter:       filter,
		snapLen:      snapLen,
		decoder:      decoder,
		pcapngWriter: pcapngWriter,
		writer:       writer,
		interfaces:   make(map[string]int),
		events:       make(chan *types.Event, 1024),
		nameEvents:   make(chan *nameEvent, 32),
	}

	if p.decoder != DecoderInternal {
		go p.populateDNS(context.TODO())
	}
	go p.run()
	return p
}

func (p *TCPDumpParser) getPodInterface(event *types.Event) int {
	p.interfacesLock.RLock()
	if id, ok := p.interfaces[event.Container]; ok {
		p.interfacesLock.RUnlock()
		return id
	}
	p.interfacesLock.RUnlock()
	// Define new interface
	p.interfacesLock.Lock()
	id, err := p.pcapngWriter.AddInterface(pcapgo.NgInterface{
		Name:        event.Container,
		Comment:     "",
		Description: fmt.Sprintf("Node: %s, Namespace: %s, Pod: %s", event.Node, event.Namespace, event.Pod),
		Filter:      p.filter,
		OS:          "",
		LinkType:    layers.LinkTypeEthernet,
		SnapLength:  uint32(p.snapLen),
		Statistics:  pcapgo.NgInterfaceStatistics{},
	})
	if err != nil {
		panic(fmt.Errorf("registering interface: %w", err))
	}
	p.interfaces[event.Container] = id
	p.interfacesLock.Unlock()
	return id
}

type wr struct {
	*os.File
}

func (wr *wr) Write(data []byte) (int, error) {
	defer wr.File.Sync()
	log.Printf("--\n--\n")
	return wr.File.Write(data)
}

// since pcapngWriter.WritePacket isn't thread safe, we need to serialize incoming events
func (p *TCPDumpParser) run() {
	for {
		select {
		case event := <-p.events:
			if event.Event.Type != eventtypes.NORMAL {
				log.Printf("ERROR: %s", event.Message)
				continue
			}
			if p.decoder == DecoderInternal {
				packet := gopacket.NewPacket(event.Payload, layers.LayerTypeEthernet, gopacket.NoCopy)
				fmt.Println(packet.String())
			} else {
				id := p.getPodInterface(event)
				err := p.pcapngWriter.WritePacket(gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, event.Time),
					CaptureLength:  len(event.Payload),
					Length:         int(event.OLen),
					InterfaceIndex: id,
				}, event.Payload)
				if err != nil {
					log.Printf("error: %v", err)
				}

				if p.decoder != DecoderFile {
					// If we're streaming to an application, let's flush here
					p.pcapngWriter.Flush()
				}
			}
		case nameEvent := <-p.nameEvents:
			if dnsBlock := getDNSBlock(nameEvent.IP, nameEvent.Name); dnsBlock != nil {
				p.writer.Write(dnsBlock)
			} else {
				log.Printf("got invalid IP: %s", nameEvent.IP)
			}
		}
	}
}

func (p *TCPDumpParser) TransformIntoColumns(event *types.Event) string {
	// This is a hack for now - we use "custom" output mode and have this method called to
	// forward packets to tcpdump / decode ourselves
	p.events <- event
	return ""
}
