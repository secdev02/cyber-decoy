// Package proxy implements the userspace reverse proxy. For each advertised
// service it listens on a TCP port, and for every accepted connection it opens
// a matching connection ("CONNECT") to the decoy backend and pipes bytes in
// both directions. Every session is logged.
package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/example/cyber-decoy/broker/internal/config"
)

// Proxy fans out incoming connections to their decoy backends.
type Proxy struct {
	dialTimeout time.Duration
	log         *slog.Logger

	mu        sync.Mutex
	listeners []net.Listener
}

// New builds a Proxy with the given dial timeout.
func New(dialTimeout time.Duration, log *slog.Logger) *Proxy {
	return &Proxy{
		dialTimeout: dialTimeout,
		log:         log,
	}
}

// Start binds a listener for each service and serves until ctx is cancelled.
// It returns after all listeners are bound; serving continues in goroutines.
func (p *Proxy) Start(ctx context.Context, services []config.Service) error {
	for _, svc := range services {
		ln, err := net.Listen("tcp", netJoin(svc.ListenPort))
		if err != nil {
			p.Close()
			return err
		}
		p.mu.Lock()
		p.listeners = append(p.listeners, ln)
		p.mu.Unlock()

		p.log.Info("service listening",
			"service", svc.Name,
			"listen_port", svc.ListenPort,
			"backend", svc.Backend,
		)
		go p.serve(ctx, ln, svc)
	}

	go func() {
		<-ctx.Done()
		p.Close()
	}()
	return nil
}

func (p *Proxy) serve(ctx context.Context, ln net.Listener, svc config.Service) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				p.log.Warn("accept failed", "service", svc.Name, "error", err)
				return
			}
		}
		go p.handle(ctx, conn, svc)
	}
}

func (p *Proxy) handle(ctx context.Context, client net.Conn, svc config.Service) {
	defer client.Close()

	remote := client.RemoteAddr().String()
	start := time.Now()
	p.log.Info("session opened",
		"service", svc.Name,
		"remote", remote,
		"backend", svc.Backend,
	)

	dialer := net.Dialer{Timeout: p.dialTimeout}
	backend, err := dialer.DialContext(ctx, "tcp", svc.Backend)
	if err != nil {
		p.log.Warn("backend connect failed",
			"service", svc.Name,
			"remote", remote,
			"backend", svc.Backend,
			"error", err,
		)
		return
	}
	defer backend.Close()

	up, down := pipe(client, backend)

	p.log.Info("session closed",
		"service", svc.Name,
		"remote", remote,
		"bytes_client_to_backend", up,
		"bytes_backend_to_client", down,
		"duration_ms", time.Since(start).Milliseconds(),
	)
}

// pipe copies bytes in both directions and returns the byte counts once either
// side closes. It reports client->backend and backend->client totals.
func pipe(client, backend net.Conn) (int64, int64) {
	var wg sync.WaitGroup
	var up, down int64

	wg.Add(2)
	go func() {
		defer wg.Done()
		up, _ = io.Copy(backend, client)
		halfClose(backend)
	}()
	go func() {
		defer wg.Done()
		down, _ = io.Copy(client, backend)
		halfClose(client)
	}()
	wg.Wait()
	return up, down
}

// halfClose closes the write side of a TCP connection when possible so the peer
// observes EOF without tearing down the read direction.
func halfClose(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
}

// Close shuts every listener down.
func (p *Proxy) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, ln := range p.listeners {
		_ = ln.Close()
	}
	p.listeners = nil
}

func netJoin(port int) string {
	return net.JoinHostPort("0.0.0.0", itoa(port))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [6]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
