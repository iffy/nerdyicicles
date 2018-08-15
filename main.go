package main

// 

import (
    "bytes"
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "log"
    "net"
    "os"
    "time"
)

var (
    logger       *log.Logger
    appstate     Appstate
    device       string = "en0"
    snapshot_len int32  = 1024
    promiscuous  bool   = true
    err          error
    timeout      time.Duration = 30 * time.Second
    handle       *pcap.Handle
)

type Device struct {
    Name string
    Mac string
    Addresses []pcap.InterfaceAddress
}
func (d Device) String() string {
    return fmt.Sprintf("{Device %v %v %v}", d.Name, d.Mac, d.Addresses)
}

type MonitoredDevice struct {
    Address net.IP
    Netmask net.IPMask
    DeviceName string
    Mac string
    GatewayIP net.IP
    Handle *pcap.Handle
}

type Appstate struct {
    LocalDevices []Device
    Monitors []MonitoredDevice
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

// getDevices gets a list of Devices
func getDevices() ([]Device) {
    var ret []Device
    macs := getMacs()
    all_ips := getIPAddresses()

    for name, mac := range macs {
        ips := all_ips[name]
        device := Device{
            Name: name,
            Mac: mac,
            Addresses: ips,
        }
        ret = append(ret, device)
    }
    return ret
}

func sendARP(handle *pcap.Handle, operation uint16, arpsrc addresspair, arpdst addresspair, hwsrc string, hwdst string) {
    var (
        rawBytes     []byte
    )

    // Convert everything to bytes
    arpsrchw, err := net.ParseMAC(arpsrc.Mac)
    if err != nil {
        log.Fatal(err)
    }
    arpsrcip := net.ParseIP(arpsrc.Address)
    arpdsthw, err := net.ParseMAC(arpdst.Mac)
    if err != nil {
        log.Fatal(err)
    }
    arpdstip := net.ParseIP(arpdst.Address)

    // Actual src/dst for the ethernet portion
    srcmac, err := net.ParseMAC(hwsrc)
    if err != nil {
        log.Fatal(err)
    }
    dstmac, err := net.ParseMAC(hwdst)
    if err != nil {
        log.Fatal(err)
    }

    logger.Println("Making ARP packet:", arpsrchw, arpsrcip, arpdsthw, arpdstip)
    logger.Println("Ethernet src/dst:", srcmac, dstmac)

    ethernetLayer := &layers.Ethernet{
        SrcMAC: srcmac,
        DstMAC: dstmac,
        EthernetType: layers.EthernetTypeARP,
    }
    arpLayer := &layers.ARP{
        AddrType: layers.LinkTypeEthernet,
        Protocol: layers.EthernetTypeIPv4,
        HwAddressSize: 6,
        ProtAddressSize: 4,
        Operation: operation,
        SourceHwAddress: arpsrchw,
        SourceProtAddress: arpsrcip,
        DstHwAddress: arpdsthw,
        DstProtAddress: arpdstip,
    }
    // And create the packet with the layers
    buffer := gopacket.NewSerializeBuffer()
    opts := gopacket.SerializeOptions{
        FixLengths: true,
        ComputeChecksums: true,
    }
    gopacket.SerializeLayers(buffer, opts,
        ethernetLayer,
        arpLayer,
        gopacket.Payload(rawBytes),
    )
    outgoingPacket := buffer.Bytes()
    logger.Println("going to send", buffer)
    logger.Println("outgoingPacket", outgoingPacket)

    // Send our packet
    err = handle.WritePacketData(outgoingPacket)
    if err != nil {
        log.Fatal(err)
    }
    logger.Println("sent")
}

// watchArp returns a channel of addresspairs corresponding to the
// ARP requests seen
func watchArp(handle *pcap.Handle) (chan addresspair) {
    pipe := make(chan addresspair)
    go func() {
        // Set filter
        var filter string = "arp or rarp"
        err = handle.SetBPFFilter(filter)
        if err != nil {
            log.Fatal(err)
        }
        logger.Println("Capturing ARP on", device)

        packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
        for packet := range packetSource.Packets() {

            logger.Println("PACKET", packet.Data())

            ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
            if ethernetLayer != nil {
                ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)

                srchw := net.HardwareAddr(ethernetPacket.SrcMAC).String()
                dsthw := net.HardwareAddr(ethernetPacket.DstMAC).String()
                logger.Printf("ETHERNET %v -> %v\n", srchw, dsthw)
            }

            arpLayer := packet.Layer(layers.LayerTypeARP)
            if arpLayer != nil {
                arpPacket, _ := arpLayer.(*layers.ARP)
                // logger.Println(arpPacket)

                srchw := net.HardwareAddr(arpPacket.SourceHwAddress).String()
                srcip := net.IP(arpPacket.SourceProtAddress).String()
                
                dsthw := net.HardwareAddr(arpPacket.DstHwAddress).String()
                dstip := net.IP(arpPacket.DstProtAddress).String()

                if arpPacket.Operation == layers.ARPRequest {
                    // REQUEST
                    logger.Printf("Request from %v (%v) for %v (%v)\n", srchw, srcip, dsthw, dstip)
                } else if (arpPacket.Operation == layers.ARPReply) {
                    // REPLY
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

func refreshState() {
    logger.Println("Refreshing state...")
    appstate.LocalDevices = getDevices()
    logger.Println("State:", appstate)
}

func startMonitor(device string, ip string, netmask string, mac string) {
    logger.Println("Start monitor", device, ip, netmask, mac)

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

    monitor := MonitoredDevice{
        Address: net.ParseIP(ip),
        // Netmask: net.IPMask
        DeviceName: device,
        Mac: mac,
        // GatewayIP net.IP
        Handle: handle,
    }
    appstate.Monitors = append(appstate.Monitors, monitor)

    arplog := watchArp(handle)

    go func() {
        logger.Println("loop start")
        for {
            select {
            case pair := <- arplog:
                logger.Println("pair", pair)
                // mac2ip[pair.Mac] = pair.Address
                // ip2mac[pair.Address] = pair.Mac
            // case <-chan2:

            //     logger.Println("Testing sending ARP")
            //     sendARP(handle,
            //         layers.ARPReply,
            //         addresspair{
            //             Mac: my_mac,
            //             Address: my_ip,
            //         },
            //         addresspair{
            //             Mac: gateway_mac,
            //             Address: gateway_ip,
            //         },
            //         my_mac,
            //         gateway_mac,
            //     )
            // }
            }
        }
    }()
}

func stopMonitor(i int) {
    logger.Println("Stopping monitor", i)
    mon := appstate.Monitors[i]
    logger.Println("Stopping monitor", mon)
    
}

func main() {
    logger = log.New(os.Stderr, "[nerdyicicles] ", log.LstdFlags)

    refreshState()

    logger.Println("Starting web server")
    StartWeb()
}
