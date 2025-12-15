package nwucp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/free5gc/aper"
	"github.com/free5gc/n3iwue/internal/gre"
	"github.com/free5gc/n3iwue/internal/logger"
	"github.com/free5gc/n3iwue/internal/packet/nasPacket"
	context "github.com/free5gc/n3iwue/pkg/context"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapConvert"
	"github.com/free5gc/ngap/ngapType"
)

func (s *Server) handleEvent(evt context.NwucpEvt) {
	switch t := evt.(type) {
	case *context.StartNwucpConnEvt:
		s.handleStartNwucpConnEvt()
	case *context.HandleRegistrationAcceptEvt:
		s.handleRegistrationAccept(t)
	case *context.HandleDLNASTransportEvt:
		s.handleDLNASTransport(t)
	case *context.StartPduSessionEstablishmentEvt:
		s.handleStartPduSessionEstablishmentEvt()
	case *context.SendDeregistrationEvt:
		s.handleSendDeregistrationEvt()
	case *context.HandleDeregistrationReqUeTerminatedEvt:
		s.handleDeregistrationReqUeTerminated(t)
	}
}

func (s *Server) handleStartNwucpConnEvt() {
	errChan := make(chan error)

	s.serverWg.Add(1)
	go s.serveConn(errChan)
	if err, ok := <-errChan; ok {
		logger.NWuCPLog.Errorf("NWUCP service startup failed: %+v", err)
		return
	}
}

func (s *Server) handleRegistrationAccept(evt *context.HandleRegistrationAcceptEvt) {
	nwucpLog := logger.NWuCPLog
	nwucpLog.Tracef("Get Registration Accept")

	n3ueSelf := s.Context()
	nasMsg := evt.NasMsg
	n3ueSelf.RanUeContext.DLCount.AddOne()
	n3ueSelf.GUTI = nasMsg.GmmMessage.RegistrationAccept.GUTI5G

	// send NAS Registration Complete Msg
	pdu := nasPacket.GetRegistrationComplete(nil)
	SendNasMsg(n3ueSelf.RanUeContext, n3ueSelf.N3IWFRanUe.TCPConnection, pdu)

	s.SendProcedureEvt(context.NewSuccessRegistrationEvt())
}

func (s *Server) handleDLNASTransport(evt *context.HandleDLNASTransportEvt) {
	nwucpLog := logger.NWuCPLog
	nwucpLog.Tracef("Get DLNAS Transport")

	n3ueSelf := s.Context()
	nasMsg := evt.NasMsg

	payloadContainer := nasMsg.GmmMessage.DLNASTransport.PayloadContainer
	payloadType := nasMsg.GmmMessage.DLNASTransport.SpareHalfOctetAndPayloadContainerType.GetPayloadContainerType()
	payloadLen := int(payloadContainer.Len)
	if payloadLen == 0 {
		nwucpLog.Warnf("DL NAS Transport received empty payload (type 0x%x)", payloadType)
		return
	}

	payloadBytes := make([]byte, payloadLen)
	copy(payloadBytes, payloadContainer.Buffer[:payloadLen])

	if payloadType != nasMessage.PayloadContainerTypeN1SMInfo {
		s.handleN2Payload(payloadType, payloadBytes)
		return
	}

	nasPayload := payloadBytes
	if err := nasMsg.GsmMessageDecode(&nasPayload); err != nil {
		nwucpLog.Warnf("NAS Decode Fail for DL NAS Transport payload (type 0x%x): %+v",
			payloadType, err)
		s.handleN2Payload(payloadType, payloadBytes)
		return
	}

	switch nasMsg.GsmMessage.GetMessageType() {
	case nas.MsgTypePDUSessionEstablishmentAccept:
		nwucpLog.Tracef("Get PDUSession Establishment Accept")

		pduAddress, err := nasPacket.GetPDUAddress(nasMsg.GsmMessage.PDUSessionEstablishmentAccept)
		if err != nil {
			nwucpLog.Errorf("GetPDUAddress Fail: %+v", err)
			return
		}

		nwucpLog.Infof("PDU Address: %s", pduAddress.String())
		n3ueSelf.N3ueInfo.DnIPAddr = pduAddress.String()

		newGREName := fmt.Sprintf("%s-id-%d", n3ueSelf.N3ueInfo.GreIfaceName, n3ueSelf.N3ueInfo.XfrmiId)

		var linkGREs map[uint8]*netlink.Link
		if linkGREs, err = gre.SetupGreTunnels(newGREName, n3ueSelf.TemporaryXfrmiName, n3ueSelf.UEInnerAddr.IP,
			n3ueSelf.TemporaryUPIPAddr, pduAddress, n3ueSelf.TemporaryQosInfo); err != nil {
			nwucpLog.Errorf("Setup GRE tunnel %s Fail: %+v", newGREName, err)
			return
		}

		qfiToTargetMap, err := nasPacket.GetQFItoTargetMap(nasMsg.PDUSessionEstablishmentAccept)
		if err != nil {
			nwucpLog.Errorf("GetQFItoTargetMap Fail: %+v", err)
			return
		}

		// Add route
		for qfi, link := range linkGREs {
			tunnel := *link
			priority := 1 // lower is higher (1 ~ 7)

			var remoteAddress nasType.PacketFilterIPv4RemoteAddress
			var ok bool
			if qfi == uint8(1) { // default qfi
				remoteAddress.Address = net.IPv4zero
				remoteAddress.Mask = net.IPv4Mask(0, 0, 0, 0)
				priority = 7
			} else if remoteAddress, ok = qfiToTargetMap[qfi]; !ok {
				nwucpLog.Errorf("not found target address for QFI [%v] from NAS", qfi)
				continue
			}

			nwucpLog.Infof("Add route: QFI[%+v] remote address[%+v]", qfi, remoteAddress)
			upRoute := &netlink.Route{
				LinkIndex: tunnel.Attrs().Index,
				Dst: &net.IPNet{
					IP:   remoteAddress.Address,
					Mask: remoteAddress.Mask,
				},
				Priority: priority,
			}
			if err := netlink.RouteAdd(upRoute); err != nil {
				nwucpLog.Warnf("netlink.RouteAdd: %+v", err)
			}
		}

		n3ueSelf.PduSessionCount++
		s.SendProcedureEvt(context.NewPduSessionEstablishedEvt())
	default:
		nwucpLog.Warnf("Unhandled DL NAS Transport message type: 0x%x", nasMsg.GsmMessage.GetMessageType())
	}
}

func (s *Server) handleN2Payload(payloadType uint8, payload []byte) {
	nwucpLog := logger.NWuCPLog

	if len(payload) == 0 {
		nwucpLog.Warnf("DL NAS Transport carried empty N2 payload (type 0x%x)", payloadType)
		return
	}

	ngapPdu, err := ngap.Decoder(payload)
	if err != nil {
		nwucpLog.Errorf("Failed to decode N2 payload (type 0x%x): %+v", payloadType, err)
		return
	}
	if ngapPdu == nil {
		nwucpLog.Warnf("NGAP decoder returned nil for N2 payload (type 0x%x)", payloadType)
		return
	}

	switch ngapPdu.Present {
	case ngapType.NGAPPDUPresentSuccessfulOutcome:
		successful := ngapPdu.SuccessfulOutcome
		if successful == nil {
			nwucpLog.Warnf("SuccessfulOutcome without content for N2 payload (type 0x%x)", payloadType)
			return
		}
		if successful.ProcedureCode.Value == ngapType.ProcedureCodeHandoverPreparation &&
			successful.Value.Present == ngapType.SuccessfulOutcomePresentHandoverCommand &&
			successful.Value.HandoverCommand != nil {
			s.handleHandoverCommand(payload, successful.Value.HandoverCommand)
			return
		}
		nwucpLog.Warnf("Unhandled SuccessfulOutcome NGAP message (procedure=%d, value=%d)",
			successful.ProcedureCode.Value, successful.Value.Present)
	case ngapType.NGAPPDUPresentInitiatingMessage:
		var proc int64
		if ngapPdu.InitiatingMessage != nil {
			proc = ngapPdu.InitiatingMessage.ProcedureCode.Value
		}
		nwucpLog.Warnf("Unhandled InitiatingMessage NGAP payload (type 0x%x, procedure=%d)", payloadType, proc)
	case ngapType.NGAPPDUPresentUnsuccessfulOutcome:
		var proc int64
		if ngapPdu.UnsuccessfulOutcome != nil {
			proc = ngapPdu.UnsuccessfulOutcome.ProcedureCode.Value
		}
		nwucpLog.Warnf("Unhandled UnsuccessfulOutcome NGAP payload (type 0x%x, procedure=%d)", payloadType, proc)
	default:
		nwucpLog.Warnf("Unhandled NGAP payload (type 0x%x, present=%d)", payloadType, ngapPdu.Present)
	}
}

func (s *Server) handleHandoverCommand(raw []byte, command *ngapType.HandoverCommand) {
	nwucpLog := logger.NWuCPLog
	if command == nil {
		nwucpLog.Warnf("Received nil Handover Command payload")
		return
	}

	n3ueSelf := s.Context()
	info := &context.HandoverCommandInfo{
		RawPdu:     append([]byte(nil), raw...),
		ReceivedAt: time.Now(),
	}

	for _, ie := range command.ProtocolIEs.List {
		switch ie.Value.Present {
		case ngapType.HandoverCommandIEsPresentAMFUENGAPID:
			if ie.Value.AMFUENGAPID != nil {
				info.AmfUeNgapID = ie.Value.AMFUENGAPID.Value
			}
		case ngapType.HandoverCommandIEsPresentRANUENGAPID:
			if ie.Value.RANUENGAPID != nil {
				info.RanUeNgapID = ie.Value.RANUENGAPID.Value
			}
		case ngapType.HandoverCommandIEsPresentHandoverType:
			if ie.Value.HandoverType != nil {
				info.HandoverType = uint64(ie.Value.HandoverType.Value)
			}
		case ngapType.HandoverCommandIEsPresentNASSecurityParametersFromNGRAN:
			if ie.Value.NASSecurityParametersFromNGRAN != nil {
				info.NasSecurityParameters = append([]byte(nil),
					ie.Value.NASSecurityParametersFromNGRAN.Value...)
			}
		case ngapType.HandoverCommandIEsPresentPDUSessionResourceHandoverList:
			info.PduSessionResourceList = ie.Value.PDUSessionResourceHandoverList
		case ngapType.HandoverCommandIEsPresentPDUSessionResourceToReleaseListHOCmd:
			info.PduSessionResourceToReleaseList = ie.Value.PDUSessionResourceToReleaseListHOCmd
		case ngapType.HandoverCommandIEsPresentTargetToSourceTransparentContainer:
			if ie.Value.TargetToSourceTransparentContainer != nil {
				info.TargetToSourceTransparentContainer = append([]byte(nil),
					ie.Value.TargetToSourceTransparentContainer.Value...)
			}
		}
	}

	n3ueSelf.LastHandoverCommand = info

	admitted := 0
	if info.PduSessionResourceList != nil {
		admitted = len(info.PduSessionResourceList.List)
	}
	release := 0
	if info.PduSessionResourceToReleaseList != nil {
		release = len(info.PduSessionResourceToReleaseList.List)
	}

	nwucpLog.Infof(
		"Received Handover Command: AMF-UE-NGAP-ID=%d RAN-UE-NGAP-ID=%d Type=%d admittedSessions=%d releaseSessions=%d",
		info.AmfUeNgapID,
		info.RanUeNgapID,
		info.HandoverType,
		admitted,
		release,
	)

	execCtx, err := buildHandoverExecutionContext(info)
	if err != nil {
		nwucpLog.Errorf("Failed to prepare handover execution context: %+v", err)
		return
	}
	execCtx.Command = info
	n3ueSelf.PendingHandover = execCtx
	n3ueSelf.NeedMobilityRegUpdate = true

	nwucpLog.Infof("Prepared handover context towards target %s (%d tunnels)",
		execCtx.TargetN3iwfIP, len(execCtx.Tunnels))

	s.SendProcedureEvt(context.NewStartHandoverEvt())
}

func buildHandoverExecutionContext(info *context.HandoverCommandInfo) (*context.HandoverExecutionContext, error) {
	if info == nil {
		return nil, fmt.Errorf("handover command info is nil")
	}

	exec := &context.HandoverExecutionContext{
		SourceAmfUeNgapID: info.AmfUeNgapID,
		SourceRanUeNgapID: info.RanUeNgapID,
	}

	if info.PduSessionResourceList == nil || len(info.PduSessionResourceList.List) == 0 {
		return nil, fmt.Errorf("handover command missing PDU session resource list")
	}

	for _, item := range info.PduSessionResourceList.List {
		tunnel := context.HandoverTunnelInfo{
			PDUSessionID: item.PDUSessionID.Value,
			RawTransfer:  append([]byte(nil), item.HandoverCommandTransfer...),
		}

		transfer, err := decodeHandoverCommandTransfer(item.HandoverCommandTransfer)
		if err != nil {
			return nil, fmt.Errorf("decode handover command transfer: %w", err)
		}

		if transfer.DLForwardingUPTNLInformation != nil &&
			transfer.DLForwardingUPTNLInformation.Present == ngapType.UPTransportLayerInformationPresentGTPTunnel &&
			transfer.DLForwardingUPTNLInformation.GTPTunnel != nil {

			ipv4, ipv6 := ngapConvert.IPAddressToString(
				transfer.DLForwardingUPTNLInformation.GTPTunnel.TransportLayerAddress,
			)
			if ipv4 != "" {
				if ip := net.ParseIP(ipv4); ip != nil {
					tunnel.TargetIP = ip
					if exec.TargetN3iwfIP == nil {
						exec.TargetN3iwfIP = ip
					}
				}
			} else if ipv6 != "" {
				if ip := net.ParseIP(ipv6); ip != nil {
					tunnel.TargetIP = ip
					if exec.TargetN3iwfIP == nil {
						exec.TargetN3iwfIP = ip
					}
				}
			}

			teidBytes := []byte(transfer.DLForwardingUPTNLInformation.GTPTunnel.GTPTEID.Value)
			if len(teidBytes) >= 4 {
				tunnel.TargetTEID = binary.BigEndian.Uint32(teidBytes[len(teidBytes)-4:])
			}
		}

		exec.Tunnels = append(exec.Tunnels, tunnel)
	}

	if exec.TargetN3iwfIP == nil {
		return nil, fmt.Errorf("no transport layer address found in handover command")
	}

	return exec, nil
}

func decodeHandoverCommandTransfer(data []byte) (*ngapType.HandoverCommandTransfer, error) {
	transfer := new(ngapType.HandoverCommandTransfer)
	if len(data) == 0 {
		return transfer, nil
	}
	if err := aper.UnmarshalWithParams(data, transfer, "valueExt"); err != nil {
		return nil, err
	}
	return transfer, nil
}

func (s *Server) handleStartPduSessionEstablishmentEvt() {
	nwucpLog := logger.NWuCPLog
	nwucpLog.Tracef("Get Start PduSession Establishment")

	n3ueSelf := s.Context()
	err := SendPduSessionEstablishmentRequest(n3ueSelf.RanUeContext, n3ueSelf.N3IWFRanUe.TCPConnection, n3ueSelf.PduSessionCount)
	if err != nil {
		nwucpLog.Errorf("SendPduSessionEstablishmentRequest Fail: %+v", err)
		return
	}
}

func (s *Server) handleSendDeregistrationEvt() {
	nwucpLog := logger.NWuCPLog
	nwucpLog.Tracef("Get Send Deregistration")

	s.SendDeregistration()
}

func (s *Server) handleDeregistrationReqUeTerminated(evt *context.HandleDeregistrationReqUeTerminatedEvt) {
	nwucpLog := logger.NWuCPLog
	nwucpLog.Tracef("Get Deregistration Request UE Terminated")

	n3ueSelf := s.Context()
	nasMsg := evt.NasMsg
	deregistrationRequest := nasMsg.GmmMessage.DeregistrationRequestUETerminatedDeregistration
	if deregistrationRequest == nil {
		nwucpLog.Errorf("Deregistration Request UE Terminated is nil")
		return
	}

	deregType := deregistrationRequest.SpareHalfOctetAndDeregistrationType
	deregistrationAccept := nasPacket.GetDeregistrationAccept()
	if deregType.GetReRegistrationRequired() == 1 {
		nwucpLog.Infof("handleDeregistrationReqUeTerminated(): Core network triggered re-registration required")
		n3ueSelf.ReRegistrationRequired = true
	}

	// Send Deregistration Accept
	SendNasMsg(n3ueSelf.RanUeContext, n3ueSelf.N3IWFRanUe.TCPConnection, deregistrationAccept)

	// Stop TCP connection
	s.StopTCPConnection()
}
