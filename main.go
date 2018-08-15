package main

// 

import (
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "log"
    "os"
    "strings"
    "time"
    "net"
    "bytes"
)

var (
    logger       *log.Logger
    device       string = "en0"
    snapshot_len int32  = 1024
    promiscuous  bool   = true
    err          error
    timeout      time.Duration = 30 * time.Second
    handle       *pcap.Handle
)

type appstate struct {
    Macs map[string]string
    Addresses map[string][]pcap.InterfaceAddress
}

type addresspair struct {
    Mac string
    Address string
}

// getMacs returns a current list of interfaces and their MAC address
func getMacs() (map[string]string) {
    ret := make(map[string]string)
    interfaces, err := net.Interfaces()
    if err == nil {
        for _, i := range interfaces {
            if i.Flags&net.FlagUp != 0 && bytes.Compare(i.HardwareAddr, nil) != 0 {
                ret[i.Name] = i.HardwareAddr.String()
            }
        }
    }
    return ret
}

// getIPAddresses returns a mapping of device names to ip addresses
func getIPAddresses() (map[string][]pcap.InterfaceAddress) {
    // Find all devices
    devices, err := pcap.FindAllDevs()
    if err != nil {
        log.Fatal(err)
    }
    ret := make(map[string][]pcap.InterfaceAddress)
    for _, device := range devices {
        var ips []pcap.InterfaceAddress;
        for _, address := range device.Addresses {
            ips = append(ips, address)
        }
        ret[device.Name] = ips    
    }
    return ret
}

// lookFor
func watchArp(device string) (chan addresspair) {
    pipe := make(chan addresspair)
    go func() {
        // Open device
        var (
            snapshot_len int32  = 1024
            promiscuous  bool   = true
            err          error
            timeout      time.Duration = -1 * time.Second
            handle       *pcap.Handle
        )
        handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
        if err != nil {
            log.Fatal(err)
        }
        defer handle.Close()

        // Set filter
        var filter string = "arp or rarp"
        err = handle.SetBPFFilter(filter)
        if err != nil {
            log.Fatal(err)
        }
        logger.Println("Capturing ARP on", device)

        packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
        for packet := range packetSource.Packets() {

            arpLayer := packet.Layer(layers.LayerTypeARP)
            if arpLayer != nil {
                arpPacket, _ := arpLayer.(*layers.ARP)

                srchw := net.HardwareAddr(arpPacket.SourceHwAddress).String()
                srcip := net.IP(arpPacket.SourceProtAddress).String()
                
                dsthw := net.HardwareAddr(arpPacket.DstHwAddress).String()
                dstip := net.IP(arpPacket.DstProtAddress).String()

                if arpPacket.Operation == 1 {
                    // request
                    // dsthw is ignored
                    logger.Printf("Request from %v (%v) for %v (%v)\n", srchw, srcip, dsthw, dstip)
                } else {
                    // reply
                    logger.Printf("Reply from %v (%v) ==> %v (%v)\n", srchw, srcip, dsthw, dstip)
                    pipe <- addresspair{
                        Mac: srchw,
                        Address: srcip,
                    }
                }
            }
        }
    }()
    return pipe
}

func refreshState() (appstate) {
    logger.Println("Refreshing state...")
    macs := getMacs()
    ips := getIPAddresses()
    state := appstate{
        Macs: macs,
        Addresses: ips,
    }
    logger.Println("State:", state)
    return state
}

func main() {
    logger = log.New(os.Stderr, "[nerdyicicles] ", log.LstdFlags)
    ticker := time.Tick(60 * time.Second)

    mac2ip := make(map[string]string)
    ip2mac := make(map[string]string)

    state := refreshState()

    chan1 := watchArp("en0")

    for {
        select {
        case <- ticker:
            state = refreshState()
            logger.Println(state.Macs)
        case pair := <- chan1:
            logger.Println("pair", pair)
            mac2ip[pair.Mac] = pair.Address
            ip2mac[pair.Address] = pair.Mac
        }
    }

}
