// Command broker is the decoy front door. It attaches an eBPF classifier to
// observe every inbound connection attempt, then reverse-proxies advertised
// service ports (SSH/RDP/SMB by default) to isolated decoy containers.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/example/cyber-decoy/broker/internal/bpf"
	"github.com/example/cyber-decoy/broker/internal/config"
	"github.com/example/cyber-decoy/broker/internal/proxy"
)

func main() {
	cfgPath := flag.String("config", "/opt/decoy/config.yaml", "path to config file")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("load config", "error", err)
		os.Exit(1)
	}

	services := cfg.EnabledServices()
	log.Info("broker starting",
		"interface", cfg.Interface,
		"services", len(services),
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Best effort eBPF observation. If it cannot attach (for example, an old
	// kernel or missing privileges), the proxy still runs so the decoy stays
	// functional. The failure is logged loudly.
	loader := startObservation(cfg, services, log)
	if loader != nil {
		defer loader.Close()
	}

	p := proxy.New(time.Duration(cfg.DialTimeoutSeconds)*time.Second, log)
	if err := p.Start(ctx, services); err != nil {
		log.Error("start proxy", "error", err)
		os.Exit(1)
	}

	<-ctx.Done()
	log.Info("broker shutting down")
	p.Close()
}

func startObservation(cfg *config.Config, services []config.Service, log *slog.Logger) *bpf.Loader {
	loader, err := bpf.Load(cfg.BPFObject)
	if err != nil {
		log.Warn("ebpf disabled: load failed", "error", err)
		return nil
	}

	ports := make([]uint16, 0, len(services))
	for _, s := range services {
		ports = append(ports, uint16(s.ListenPort))
	}
	if err := loader.SetAdvertisedPorts(ports); err != nil {
		log.Warn("ebpf disabled: set ports failed", "error", err)
		loader.Close()
		return nil
	}

	if err := loader.Attach(cfg.Interface); err != nil {
		log.Warn("ebpf disabled: attach failed", "error", err, "interface", cfg.Interface)
		loader.Close()
		return nil
	}

	log.Info("ebpf classifier attached", "interface", cfg.Interface)

	go func() {
		err := loader.Events(func(ev bpf.ConnEvent) {
			log.Info("probe observed",
				"src", ev.SrcAddr(),
				"src_port", ev.SrcPort,
				"dst_port", ev.DstPort,
				"advertised", ev.IsAdvertised == 1,
				"tcp_flags", ev.TCPFlags,
			)
		})
		if err != nil {
			log.Warn("event stream stopped", "error", err)
		}
	}()

	return loader
}
