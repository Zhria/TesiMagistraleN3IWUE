package procedure

import (
	"context"
	"fmt"
	"net"
	"runtime/debug"
	"sync"
	"time"

	"github.com/go-ping/ping"
	"github.com/sirupsen/logrus"

	"github.com/free5gc/n3iwue/internal/logger"
	n3iwue_context "github.com/free5gc/n3iwue/pkg/context"
	"github.com/free5gc/n3iwue/pkg/factory"
	"github.com/free5gc/n3iwue/pkg/ike"
)

var AppLog *logrus.Entry

const (
	PROCEDURE_EVENT_CHAN_SIZE = 128
)

func init() {
	// init logger
	AppLog = logger.AppLog
}

type N3iwue interface {
	Config() *factory.Config
	Context() *n3iwue_context.N3UE
	SendIkeEvt(evt n3iwue_context.IkeEvt)
	SendNwucpEvt(evt n3iwue_context.NwucpEvt)
	SignalDeregistrationComplete()
	TriggerGracefulShutdown(reason string)
}

type Server struct {
	N3iwue
	rcvEvtCh     chan n3iwue_context.ProcedureEvt
	serverCtx    context.Context
	serverCancel context.CancelFunc
	serverWg     sync.WaitGroup
}

func NewServer(n3iwue N3iwue) (*Server, error) {
	serverCtx, serverCancel := context.WithCancel(context.Background())
	return &Server{
		N3iwue:       n3iwue,
		serverCtx:    serverCtx,
		serverCancel: serverCancel,
		rcvEvtCh:     make(chan n3iwue_context.ProcedureEvt, PROCEDURE_EVENT_CHAN_SIZE),
	}, nil
}

func (s *Server) Run(wg *sync.WaitGroup) {
	wg.Add(1)
	s.serverWg.Add(1)
	go s.dispatcher(wg)

	// Start Procedure
	s.SendProcedureEvt(n3iwue_context.NewStartRegistrationEvt())
}

func (s *Server) dispatcher(wg *sync.WaitGroup) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			AppLog.Errorf("panic: %v\n%s", p, string(debug.Stack()))
		}
		AppLog.Infof("Procedure event dispatcher stopped")
		s.serverWg.Done()
		wg.Done()
	}()

	for {
		select {
		case evt := <-s.rcvEvtCh:
			s.handleEvent(evt)
		case <-s.serverCtx.Done():
			AppLog.Infof("Procedure event dispatcher stopped by server context")
			return
		}
	}
}

func (s *Server) handleEvent(evt n3iwue_context.ProcedureEvt) {
	switch evt.(type) {
	case *n3iwue_context.StartRegistrationEvt:
		// Start IKE SA Establishment
		s.SendIkeEvt(n3iwue_context.NewStartIkeSaEstablishmentEvt())
	case *n3iwue_context.RestartRegistrationEvt:
		AppLog.Warnf("Restarting registration due to connection failure")
		s.SendIkeEvt(n3iwue_context.NewStartIkeSaEstablishmentEvt())
	case *n3iwue_context.NwucpChildSaCreatedEvt:
		// Establish NWUCP connection with N3IWF
		s.SendNwucpEvt(n3iwue_context.NewStartNwucpConnEvt())
	case *n3iwue_context.ReconnectNwucpEvt:
		AppLog.Info("Reconnecting NWUCP (NAS over TCP)")
		// T5: NWuCP reconnect
		n3ueCtx := s.Context()
		if n3ueCtx != nil && !n3ueCtx.HandoverTimingStart.IsZero() {
			AppLog.Infof("HANDOVER_TIMING: phase=nwucp_reconnect elapsed=%s", time.Since(n3ueCtx.HandoverTimingStart))
		}
		s.SendNwucpEvt(n3iwue_context.NewStartNwucpConnEvt())
	case *n3iwue_context.SuccessRegistrationEvt:
		n3ueSelf := s.Context()
		if n3ueSelf != nil && n3ueSelf.PendingHandover != nil && !n3ueSelf.MobikeRejected {
			AppLog.Info("Mobility registration update completed after handover; skipping PDU Session establishment")
			// T6: Handover complete
			if !n3ueSelf.HandoverTimingStart.IsZero() {
				total := time.Since(n3ueSelf.HandoverTimingStart)
				AppLog.Infof("HANDOVER_TIMING: phase=handover_complete elapsed=%s total=%s", total, total)
				n3ueSelf.HandoverTimingStart = time.Time{}
				n3ueSelf.HandoverMobikeSentAt = time.Time{}
			}
			n3ueSelf.PendingHandover = nil
			n3ueSelf.NeedMobilityRegUpdate = false
			n3ueSelf.NasNh = nil
			n3ueSelf.NasNcc = 0
			AppLog.Info("Handover completed; keep connection with N3IWF until receive SIGINT or SIGTERM")
			return
		}

		if n3ueSelf != nil && n3ueSelf.MobikeRejected {
			AppLog.Info("MOBIKE was rejected (no state-sync on target); waiting for N3IWF CREATE_CHILD_SA")
			n3ueSelf.PendingHandover = nil
			n3ueSelf.NeedMobilityRegUpdate = false
			n3ueSelf.NasNh = nil
			n3ueSelf.NasNcc = 0
			// MobikeRejected stays true so the IKE handler knows to fire
			// PduSessionEstablishedEvt when CREATE_CHILD_SA arrives.
			return
		}

		// Wait for AMF to transition from ContextSetup to Registered state
		// before sending PDU Session Establishment Request (UL NAS Transport)
		time.Sleep(100 * time.Millisecond)

		// Start PduSession Establishment
		s.SendNwucpEvt(n3iwue_context.NewStartPduSessionEstablishmentEvt())
	case *n3iwue_context.DeregistrationCompleteEvt:
		s.handleDeregistrationCompleteEvt()
	case *n3iwue_context.PduSessionEstablishedEvt:
		// Test Connectivity
		AppLog.Info("PduSession Created")
		n3ueSelf := s.Context()
		go func() {
			if err := s.TestConnectivity("9.9.9.9"); err != nil {
				AppLog.Errorf("ping fail : %+v", err)
			}
			if err := s.TestConnectivity("1.1.1.1"); err != nil {
				AppLog.Errorf("ping fail : %+v", err)
			}
			if err := s.TestConnectivity("8.8.8.8"); err != nil {
				AppLog.Errorf("ping fail : %+v", err)
			} else {
				AppLog.Infof("ULCount=%x, DLCount=%x",
					n3ueSelf.RanUeContext.ULCount.Get(),
					n3ueSelf.RanUeContext.DLCount.Get())
				AppLog.Info("Keep connection with N3IWF until receive SIGINT or SIGTERM")
			}
		}()
	case *n3iwue_context.StartHandoverEvt:
		s.handleStartHandoverEvt()
	default:
		AppLog.Errorf("Unknown procedure event: %+v", evt)
	}
}

func (s *Server) TestConnectivity(addr string) error {
	n3ueSelf := s.Context()

	// Ping remote
	pinger, err := ping.NewPinger(addr)
	if err != nil {
		return err
	}

	// Run with root
	pinger.SetPrivileged(true)

	pinger.OnRecv = func(pkt *ping.Packet) {
		AppLog.Infof("%d bytes from %s: icmp_seq=%d time=%v\n",
			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt)
	}
	pinger.OnFinish = func(stats *ping.Statistics) {
		AppLog.Infof("\n--- %s ping statistics ---\n", stats.Addr)
		AppLog.Infof("%d packets transmitted, %d packets received, %v%% packet loss\n",
			stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
		AppLog.Infof("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
			stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
	}

	pinger.Count = 5
	pinger.Timeout = 10 * time.Second
	if n3ueSelf.N3ueInfo.DnIPAddr != "" {
		pinger.Source = n3ueSelf.N3ueInfo.DnIPAddr
	}

	time.Sleep(3 * time.Second)

	if err := pinger.Run(); err != nil {
		return fmt.Errorf("Running ping failed: %+v", err)
	}

	time.Sleep(1 * time.Second)

	stats := pinger.Statistics()
	if stats.PacketsSent != stats.PacketsRecv {
		return fmt.Errorf("Ping Failed")
	}

	return nil
}

func (s *Server) SendProcedureEvt(evt n3iwue_context.ProcedureEvt) {
	select {
	case s.rcvEvtCh <- evt:
		// Event sent successfully
	default:
		AppLog.Errorf("Event channel is full, dropping Procedure event")
	}
}

func (s *Server) Stop() {
	AppLog.Infof("Starting Procedure server shutdown")
	s.serverCancel()
	s.serverWg.Wait()
	AppLog.Info("Procedure server shutdown complete")
}

func (s *Server) handleDeregistrationCompleteEvt() {
	AppLog.Info("Deregistration complete event received")

	n3ueSelf := s.Context()
	if n3ueSelf.ReRegistrationRequired {
		AppLog.Info("Re-registration required, triggering reconnection")
		// Trigger IKE reconnection
		s.SendIkeEvt(n3iwue_context.NewIkeReConnectEvt())
	} else {
		AppLog.Info("Re-registration not required, shutting down application")
		// Trigger application graceful shutdown
		s.TriggerGracefulShutdown("deregistration complete without re-registration")
	}
}

func (s *Server) handleStartHandoverEvt() {
	AppLog.Info("Start handover event received")

	n3ueSelf := s.Context()
	if n3ueSelf.PendingHandover == nil {
		AppLog.Warn("No pending handover context available")
		return
	}

	if err := s.prepareTargetIKESession(n3ueSelf.PendingHandover); err != nil {
		AppLog.Errorf("Preparing target IKE session failed: %+v", err)
		return
	}

	AppLog.Infof("Handover prep: target=%s ikePort=%d nattPort=%d tunnels=%d",
		n3ueSelf.PendingHandover.TargetN3iwfIP,
		n3ueSelf.PendingHandover.TargetIKEPort,
		n3ueSelf.PendingHandover.TargetNATTPort,
		len(n3ueSelf.PendingHandover.Tunnels))

	if len(n3ueSelf.PendingHandover.Tunnels) > 0 {
		srcInner := n3ueSelf.PendingHandover.SourceN3iwfInnerIP
		tgtInner := n3ueSelf.PendingHandover.TargetN3iwfInnerIP
		if srcInner != nil && len(srcInner) > 0 && tgtInner != nil && len(tgtInner) > 0 && srcInner.Equal(tgtInner) {
			AppLog.Infof("Skipping GRE rebuild: N3IWF inner IP unchanged (source=%s target=%s)", srcInner, tgtInner)
		} else {
			if err := s.rebuildHandoverTunnels(n3ueSelf.PendingHandover); err != nil {
				AppLog.Warnf("Updating tunnels for handover failed: %+v", err)
			}
		}
	}

	// Prefer MOBIKE UPDATE_SA_ADDRESSES (stateful IPSec) if negotiated; otherwise fall back to full IKE re-establishment.
	if n3ueSelf.N3IWFUe != nil && n3ueSelf.N3IWFUe.N3IWFIKESecurityAssociation != nil &&
		n3ueSelf.N3IWFUe.N3IWFIKESecurityAssociation.MobikeSupported {
		AppLog.Infof("Triggering MOBIKE UPDATE_SA_ADDRESSES towards target N3IWF %s", n3ueSelf.PendingHandover.TargetN3iwfIP)
		s.SendIkeEvt(n3iwue_context.NewSendMobikeUpdateEvt())
		return
	}

	AppLog.Infof("MOBIKE not available; triggering IKE re-establishment towards target N3IWF %s",
		n3ueSelf.PendingHandover.TargetN3iwfIP)
	s.SendIkeEvt(n3iwue_context.NewStartIkeSaEstablishmentEvt())
}

func (s *Server) prepareTargetIKESession(ctx *n3iwue_context.HandoverExecutionContext) error {
	if ctx == nil {
		return fmt.Errorf("handover execution context is nil")
	}
	if ctx.TargetN3iwfIP == nil {
		return fmt.Errorf("missing target N3IWF IP address")
	}

	targetIP := ctx.TargetN3iwfIP
	ikePort := ctx.TargetIKEPort
	if ikePort == 0 {
		ikePort = ike.DEFAULT_IKE_PORT
	}
	nattPort := ctx.TargetNATTPort
	if nattPort == 0 {
		nattPort = ike.DEFAULT_NATT_PORT
	}

	n3ueSelf := s.Context()
	for _, port := range []int{ike.DEFAULT_IKE_PORT, ike.DEFAULT_NATT_PORT} {
		udpInfo, ok := n3ueSelf.IKEConnection[port]
		if !ok || udpInfo == nil || udpInfo.Conn == nil {
			return fmt.Errorf("IKE connection for port %d not initialized", port)
		}
		targetPort := ikePort
		if port == ike.DEFAULT_NATT_PORT {
			targetPort = nattPort
		}
		udpInfo.N3IWFAddr = &net.UDPAddr{
			IP:   targetIP,
			Port: targetPort,
		}
	}

	// If the target indicates NAT traversal, prefer the NAT-T socket for subsequent IKE exchanges (MOBIKE)
	// and allow ESP-in-UDP to work end-to-end on the new access.
	if ctx.EnableNATT && n3ueSelf.N3IWFUe != nil {
		if nattConn := n3ueSelf.IKEConnection[ike.DEFAULT_NATT_PORT]; nattConn != nil && nattConn.Conn != nil {
			n3ueSelf.N3IWFUe.IKEConnection = nattConn
			if ikeSA := n3ueSelf.N3IWFUe.N3IWFIKESecurityAssociation; ikeSA != nil {
				ikeSA.StoreReqRetransUdpConnInfo(nattConn)
				ikeSA.StoreRspRetransUdpConnInfo(nattConn)
			}
			AppLog.Infof("Handover prep: NAT traversal requested, using UDP/%d for IKE/MOBIKE", ike.DEFAULT_NATT_PORT)
		} else {
			AppLog.Warnf("Handover prep: NAT traversal requested but UDP/%d socket unavailable; keeping UDP/%d",
				ike.DEFAULT_NATT_PORT, ike.DEFAULT_IKE_PORT)
		}
	}

	if ctx.Command != nil {
		n3ueSelf.LastHandoverCommand = ctx.Command
	}

	n3ueSelf.N3iwfInfo.IPSecIfaceAddr = targetIP.String()
	return nil
}
