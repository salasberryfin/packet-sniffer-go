package main

import (
    "fmt"
    "log"
    "flag"
    "net"
    "os"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/pcapgo"
)

// Struct to hold Flags and validate argument value
type flagStruct struct {
    set     bool
    value   string
}
// Flags
var iface_name flagStruct
var filter flagStruct
var file flagStruct

func listInterfaces() []string {
    interfaces, err := net.Interfaces()
    if err != nil {
        log.Fatal(err)
    }
    var iface_names []string
    for _, iface := range interfaces {
        iface_names = append(iface_names, iface.Name)
    }
    // Append the 'any' flag to list of interfaces
    iface_names = append(iface_names, "any")

    return iface_names
}

func selectInterfaceFromList(names []string) string {
    log.Println("The following are the available interfaces in this device:")
    for i, name := range names {
        fmt.Printf("[%d] - %q\n", i+1, name)
    }

    var iface_index int
    fmt.Printf("Select the number of the interface to use: ")
    _, err := fmt.Scanf("%d", &iface_index)
    if err != nil {
        log.Fatal(err)
    }
    if len(names) < (iface_index - 1) {
        log.Fatal("[FATAL] The requested interface does not exist.")
    }
    selected_iface_name := names[iface_index - 1]

    return selected_iface_name
}

func captureTraffic(iface_name, bpf string) {
    handle, err := pcap.OpenLive(iface_name, 1600, true, pcap.BlockForever)
    if err != nil {
        log.Fatal(err)
    }
    if bpf != "" {
        log.Printf("[INFO] Setting BPF filter: %q.\n", bpf)
        err = handle.SetBPFFilter(bpf)
        if err != nil {
            log.Fatal(err)
        }
    }
    packet_source := gopacket.NewPacketSource(handle, handle.LinkType())
    if file.set {
        log.Printf("[INFO] Will be logging packets to %q.\n", file.value)
    }
    for packet := range packet_source.Packets() {
        fmt.Println(packet.Dump())
        if file.set {
            writeToPcapFile(packet)
        }
    }
}

func writeToPcapFile(packet gopacket.Packet) {
    output_f, err := os.Create(file.value)
    w := pcapgo.NewWriter(output_f)
    w.WriteFileHeader(65536, layers.LinkTypeEthernet)
    err = w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
    if err != nil {
        log.Fatal(err)
    }
}

func (fl *flagStruct) Set(x string) error {
    fl.value = x
    fl.set = true

    return nil
}

func (fl *flagStruct) String() string {
    return fl.value
}

func init() {
    flag.Var(&iface_name, "interface", "Name of the network interface [Defaults to: lists all available interfaces].")
    flag.Var(&filter, "filter", "BPF filter to apply to the network trace. [Defaults to: no filter]")
    flag.Var(&file, "file", "Name of the file to write output PCAP to.")
}

func main() {
    flag.Parse()
    if !iface_name.set {
        log.Println("[WARNING] Interface name not set.")
        iface_names := listInterfaces()
        iface_name.value = selectInterfaceFromList(iface_names)
    } else {
        fmt.Printf("[INFO] Interface name is: %q.\n", iface_name.value)
    }
    if filter.set {
        log.Printf("[INFO] BPF filter is: %q.\n", filter.value)
    } else {
        log.Println("[INFO] No BPF filter was detected, will be left empty.")
    }

    captureTraffic(iface_name.value, filter.value)
}
