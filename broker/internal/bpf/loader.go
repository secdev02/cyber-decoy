// Package bpf loads the compiled TC classifier, attaches it to the broker's
// network interface, populates the advertised-ports map, and streams connection
// events from the ring buffer to a callback.
package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// ConnEvent mirrors struct conn_event in decoy.bpf.c. Field order and padding
// must match the C definition exactly.
type ConnEvent struct {
	SrcIP        uint32
	DstIP        uint32
	SrcPort      uint16
	DstPort      uint16
	TCPFlags     uint8
	IsAdvertised uint8
	_            [2]uint8
}

// SrcAddr renders the source IP as a dotted-quad string.
func (e ConnEvent) SrcAddr() string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], e.SrcIP)
	return net.IP(b[:]).String()
}

// Loader owns the eBPF collection and attached link.
type Loader struct {
	coll   *ebpf.Collection
	tcLink link.Link
	reader *ringbuf.Reader
}

// Load reads the object file at objPath and prepares the collection.
func Load(objPath string) (*Loader, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new collection: %w", err)
	}
	return &Loader{coll: coll}, nil
}

// SetAdvertisedPorts populates the advertised_ports map so the classifier can
// tag whether an incoming probe hit a served port.
func (l *Loader) SetAdvertisedPorts(ports []uint16) error {
	m, ok := l.coll.Maps["advertised_ports"]
	if !ok {
		return errors.New("advertised_ports map not found in object")
	}
	one := uint8(1)
	for _, p := range ports {
		if err := m.Put(p, one); err != nil {
			return fmt.Errorf("put port %d: %w", p, err)
		}
	}
	return nil
}

// Attach hooks the classifier to the named interface on TC ingress. This uses
// the TCX attach path, which requires a Linux kernel of 6.6 or newer.
func (l *Loader) Attach(ifaceName string) error {
	prog, ok := l.coll.Programs["decoy_classifier"]
	if !ok {
		return errors.New("decoy_classifier program not found in object")
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s: %w", ifaceName, err)
	}
	lnk, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   prog,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("attach tcx: %w", err)
	}
	l.tcLink = lnk

	rd, err := ringbuf.NewReader(l.coll.Maps["events"])
	if err != nil {
		return fmt.Errorf("open ringbuf: %w", err)
	}
	l.reader = rd
	return nil
}

// Events reads connection events until the reader is closed, invoking fn for
// each one. It returns when the ring buffer is closed.
func (l *Loader) Events(fn func(ConnEvent)) error {
	for {
		rec, err := l.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return err
		}
		var ev ConnEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}
		fn(ev)
	}
}

// Close detaches the program and frees resources.
func (l *Loader) Close() {
	if l.reader != nil {
		_ = l.reader.Close()
	}
	if l.tcLink != nil {
		_ = l.tcLink.Close()
	}
	if l.coll != nil {
		l.coll.Close()
	}
}
