package main

import (
    "fmt"
    "log"
    "flag"
    "net"

    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
)

type netIface struct {
    set     bool
    value   string
}
var iface_name netIface

func captureAllTraffic(iface_name string) {
    handle, err := pcap.OpenLive(iface_name, 1600, true, pcap.BlockForever)
    if err != nil {
        log.Fatal(err)
    }
    packet_source := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packet_source.Packets() {
        fmt.Println(packet)
    }

}

func listInterfaces() string {
    interfaces, err := net.Interfaces()
    if err != nil {
        log.Fatal(err)
    }

    log.Print("The following are the available interfaces in this devices:\n")
    for i, iface := range interfaces {
        fmt.Printf("[%d] - %q\n", i+1, iface.Name)
    }
    var iface_index int
    fmt.Printf("Select the number of the interface to use: ")
    _, err = fmt.Scanf("%d", &iface_index)
    if err != nil {
        log.Fatal(err)
    }
    if len(interfaces) < (iface_index - 1) {
        log.Fatal("The requested item of the list does not exist.")
    }
    iface_result := interfaces[iface_index - 1]

    return iface_result.Name
}

func (iface *netIface) Set(x string) error {
    iface.value = x
    iface.set = true

    return nil
}

func (iface *netIface) String() string {
    return iface.value
}

func init() {
    flag.Var(&iface_name, "interface", "Name of the network interface.")
}

func main() {
    flag.Parse()
    if !iface_name.set {
        log.Println("[WARNING] Interface name not set.")
        iface_name.value = listInterfaces()
    } else {
        fmt.Printf("Interface name is: %q.\n", iface_name.value)
    }

    captureAllTraffic(iface_name.value)

}
