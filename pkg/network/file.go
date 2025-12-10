package network

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/bpf"
)

type PcapReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

type FileHandle struct {
	Name      string
	Filter    string
	SnapLen   uint32
	ZeroCopy  bool
	Clustered bool
	ClusterID int
	FanOut    bool
	W         bool
	F         *os.File
	Reader    PcapReader
	FHandleW  *pcapgo.NgWriter
	BPFVM     *bpf.VM
}

func (h *FileHandle) NewFileInterface() {
	var err error
	if h.W {
		h.F, err = os.Create(h.Name)
		if err != nil {
			panic(err)
		}

		h.FHandleW, err = pcapgo.NewNgWriter(h.F, layers.LinkTypeEthernet)
		if err != nil {
			panic(err)
		}
	} else {
		h.F, err = os.Open(h.Name)
		if err != nil {
			panic(err)
		}

		var r io.Reader = h.F
		if strings.HasSuffix(h.Name, ".gz") {
			log.Debugf("Compressed input file detected, using gzip reader")
			gz, err := gzip.NewReader(h.F)
			if err != nil {
				panic(err)
			}
			r = gz
		}

		bufR := bufio.NewReader(r)
		magic, err := bufR.Peek(4)
		if err != nil {
			panic(err)
		}

		if bytes.Equal(magic, []byte{0x0A, 0x0D, 0x0D, 0x0A}) {
			log.Debugf("File format is PCAPNG")
			h.Reader, err = pcapgo.NewNgReader(bufR, pcapgo.DefaultNgReaderOptions)
		} else {
			log.Debugf("File format is legacy PCAP")
			h.Reader, err = pcapgo.NewReader(bufR)
		}

		if err != nil {
			panic(err)
		}
	}

}

func (h *FileHandle) Init(conf *HandleConfig) error {
	h.Name = conf.Name
	h.SnapLen = conf.SnapLen
	h.Filter = conf.Filter
	h.W = conf.W
	h.NewFileInterface()

	// Compile BPF filter if provided
	if h.Filter != "" && !h.W {
		log.Infof("Using BPF filter on file input: %s", h.Filter)
		pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, int(h.SnapLen), h.Filter)
		if err != nil {
			log.Errorf("BPF filter compilation error: %v", err)
			return fmt.Errorf("invalid BPF filter syntax '%s': %w", h.Filter, err)
		}

		log.Debugf("Successfully compiled BPF filter with %d instructions", len(pcapBPF))
		bpfRaw := make([]bpf.RawInstruction, len(pcapBPF))
		for i, ins := range pcapBPF {
			bpfRaw[i] = bpf.RawInstruction{
				Op: ins.Code,
				Jt: ins.Jt,
				Jf: ins.Jf,
				K:  ins.K,
			}
		}
		bpfInstructions, ok := bpf.Disassemble(bpfRaw)
		if !ok {
			return errors.New("failed to disassemble BPF instructions")
		}
		h.BPFVM, err = bpf.NewVM(bpfInstructions)
		if err != nil {
			log.Errorf("BPF VM creation error: %v", err)
			return err
		}
	}
	return nil
}

func (h *FileHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if h.ZeroCopy {
		log.Fatal("You can not read zero copy from pcap")
		return nil, gopacket.CaptureInfo{}, errors.New("You can not read zero copy from pcap")
	}

	// Read packets until we find one that matches the filter
	for {
		data, ci, err := h.Reader.ReadPacketData()
		if err != nil {
			return data, ci, err
		}

		// If no filter, return immediately
		if h.BPFVM == nil {
			return data, ci, nil
		}

		// Apply BPF filter
		matched, err := h.BPFVM.Run(data)
		if err != nil {
			log.Debugf("BPF filter error: %v", err)
			continue
		}

		if matched > 0 {
			return data, ci, nil
		}
		// Filter didn't match, read next packet
	}
}

func (h *FileHandle) WritePacketData(pkt *Packet) error {
	log.Debugf("Preparing to write packet to file")
	// Write packet to file
	pkt.Ci.InterfaceIndex = 0
	pkt.Ci.CaptureLength = len(pkt.OutBuf.Bytes())
	err := h.FHandleW.WritePacket(pkt.Ci, pkt.OutBuf.Bytes())
	if err != nil {
		log.Fatalf("Could not write the packet, error: %s", err)
		panic(err)
	}
	return nil
}

func (h *FileHandle) Stats() IfStats {
	return IfStats{
		PktRecv: 0,
		PktDrop: 0,
	}
}

func (h *FileHandle) Close() error {
	if h.W {
		h.FHandleW.Flush()
	}
	h.F.Close()
	return nil
}
