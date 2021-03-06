package HoneyBadger

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"net"
	"strings"
	"testing"
)

func TestSequenceFromPacket(t *testing.T) {
	var testSeq uint32 = 12345
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	ip := layers.IPv4{
		SrcIP:    net.IP{1, 2, 3, 4},
		DstIP:    net.IP{2, 3, 4, 5},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SYN:       true,
		SrcPort:   1,
		DstPort:   2,
		Seq:       testSeq,
		BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3}},
	}
	tcp.SetNetworkLayerForChecksum(&ip)
	gopacket.SerializeLayers(buf, opts, &ip, &tcp)
	packetData := buf.Bytes()
	seq, err := SequenceFromPacket(packetData)
	if err == nil && seq == testSeq {
		return
	} else {
		t.Error("SequenceFromPacket failed")
		t.Fail()
		return
	}

	seq, err = SequenceFromPacket([]byte{1, 2, 3})
	if err == nil {
		t.Error("SequenceFromPacket should have failed")
		t.Fail()
	}
}

func TestFlowString(t *testing.T) {
	ipFlow, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(net.IPv4(1, 2, 3, 4)), layers.NewIPEndpoint(net.IPv4(2, 3, 4, 5)))
	tcpFlow, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(layers.TCPPort(1)), layers.NewTCPPortEndpoint(layers.TCPPort(2)))
	tcpIpFlow := NewTcpIpFlowFromFlows(ipFlow, tcpFlow)
	if !strings.EqualFold("1.2.3.4:1-2.3.4.5:2", tcpIpFlow.String()) {
		t.Error("TcpIpFlow.String() fail")
		t.Fail()
	}
}

func TestFlowEqual(t *testing.T) {
	ipFlow1, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(net.IPv4(1, 2, 3, 4)), layers.NewIPEndpoint(net.IPv4(2, 3, 4, 5)))
	tcpFlow1, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(layers.TCPPort(1)), layers.NewTCPPortEndpoint(layers.TCPPort(2)))
	flow1 := NewTcpIpFlowFromFlows(ipFlow1, tcpFlow1)

	ipFlow2, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(net.IPv4(1, 2, 3, 4)), layers.NewIPEndpoint(net.IPv4(2, 3, 4, 5)))
	tcpFlow2, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(layers.TCPPort(1)), layers.NewTCPPortEndpoint(layers.TCPPort(2)))
	flow2 := NewTcpIpFlowFromFlows(ipFlow2, tcpFlow2)

	if !flow1.Equal(flow2) {
		t.Error("TcpIpFlow.Equal fail")
		t.Fail()
	}

	ipFlow3, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(net.IPv4(8, 2, 3, 4)), layers.NewIPEndpoint(net.IPv4(2, 3, 4, 5)))
	tcpFlow3, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(layers.TCPPort(1)), layers.NewTCPPortEndpoint(layers.TCPPort(2)))
	flow3 := NewTcpIpFlowFromFlows(ipFlow3, tcpFlow3)

	if flow1.Equal(flow3) {
		t.Error("TcpIpFlow.Equal fail")
		t.Fail()
	}
}
