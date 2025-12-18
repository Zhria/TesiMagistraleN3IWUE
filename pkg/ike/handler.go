package ike

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	ike_eap "github.com/free5gc/ike/eap"
	ike_message "github.com/free5gc/ike/message"
	ike_security "github.com/free5gc/ike/security"
	"github.com/free5gc/ike/security/dh"
	"github.com/free5gc/ike/security/encr"
	"github.com/free5gc/ike/security/integ"
	"github.com/free5gc/ike/security/prf"
	"github.com/free5gc/n3iwue/internal/logger"
	"github.com/free5gc/n3iwue/internal/packet/nasPacket"
	"github.com/free5gc/n3iwue/internal/packet/ngapPacket"
	"github.com/free5gc/n3iwue/internal/qos"
	n3ue_security "github.com/free5gc/n3iwue/internal/security"
	"github.com/free5gc/n3iwue/internal/util"
	context "github.com/free5gc/n3iwue/pkg/context"
	"github.com/free5gc/n3iwue/pkg/factory"
	"github.com/free5gc/n3iwue/pkg/ike/xfrm"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasConvert"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/util/ueauth"
)

var nasLog *logrus.Entry

func init() {
	nasLog = logger.NASLog
}

// IKE_AUTH state
const (
	IKEAUTH_Request = iota
	EAP_RegistrationRequest
	EAP_Authentication
	EAP_NASSecurityComplete
	IKEAUTH_Authentication
)

const targetToSourceNotifyType uint16 = 40960
const handoverFailureNotifyType uint16 = 40961

func (s *Server) handleEvent(ikeEvt context.IkeEvt) {
	switch t := ikeEvt.(type) {
	case *context.HandleIkeMsgSaInitEvt:
		// Check for retransmit before processing
		if s.shouldProcessRetransmit(t.IkeMsg, t.Packet) {
			s.handleIKESAINIT(t)
		}
	case *context.HandleIkeMsgAuthEvt:
		// Check for retransmit before processing
		if s.shouldProcessRetransmit(t.IkeMsg, t.Packet) {
			s.handleIKEAUTH(t)
		}
	case *context.HandleIkeMsgCreateChildSaEvt:
		// Check for retransmit before processing
		if s.shouldProcessRetransmit(t.IkeMsg, t.Packet) {
			s.handleCREATECHILDSA(t)
		}
	case *context.HandleIkeMsgInformationalEvt:
		// Check for retransmit before processing
		if s.shouldProcessRetransmit(t.IkeMsg, t.Packet) {
			s.handleInformational(t)
		}
	case *context.IkeRetransTimeoutEvt:
		s.handleIkeRetransTimeout()
	case *context.DpdCheckEvt:
		s.handleDpdCheck()

	// For Procedure event
	case *context.StartIkeSaEstablishmentEvt:
		s.handleStartIkeSaEstablishment()
	case *context.SendMobikeUpdateEvt:
		s.handleSendMobikeUpdate()
	case *context.IkeReConnectEvt:
		s.handleIkeReconnect()
	default:
		logger.IKELog.Errorf("Unknown IKE event: %+v", ikeEvt.Type())
	}
}

func (s *Server) handleStartIkeSaEstablishment() {
	ikeLog := logger.IKELog
	ikeLog.Infoln("Handle Start IKE SA Establishment")
	n3ueContext := s.Context()

	// Stop any existing continuous timer
	s.stopContinuousIkeSaInit()

	// Send initial IKE_SA_INIT
	s.SendIkeSaInit()

	// Set up continuous timer for IKE_SA_INIT retransmission
	retransCfg := factory.N3ueInfo.IkeRetransmit
	interval := time.Duration(retransCfg.Base) * retransCfg.ExpireTime

	n3ueContext.ContinuousIkeSaInitTimer = time.AfterFunc(interval, func() {
		s.SendIkeEvt(context.NewStartIkeSaEstablishmentEvt())
	})
}

func (s *Server) handleSendMobikeUpdate() {
	ikeLog := logger.IKELog
	n3ueSelf := s.Context()
	if n3ueSelf == nil || n3ueSelf.N3IWFUe == nil || n3ueSelf.N3IWFUe.N3IWFIKESecurityAssociation == nil {
		ikeLog.Warn("MOBIKE update requested but no active IKE SA; falling back to IKE re-establishment")
		s.SendIkeEvt(context.NewStartIkeSaEstablishmentEvt())
		return
	}

	ikeSA := n3ueSelf.N3IWFUe.N3IWFIKESecurityAssociation
	if !ikeSA.MobikeSupported {
		ikeLog.Warn("MOBIKE not negotiated; falling back to IKE re-establishment")
		s.SendIkeEvt(context.NewStartIkeSaEstablishmentEvt())
		return
	}

	localIP := net.ParseIP(n3ueSelf.N3ueInfo.IPSecIfaceAddr)
	peerIP := net.ParseIP(n3ueSelf.N3iwfInfo.IPSecIfaceAddr)
	if localIP == nil || peerIP == nil {
		ikeLog.Warnf("Invalid local/peer IP for MOBIKE (local=%q peer=%q); falling back",
			n3ueSelf.N3ueInfo.IPSecIfaceAddr, n3ueSelf.N3iwfInfo.IPSecIfaceAddr)
		s.SendIkeEvt(context.NewStartIkeSaEstablishmentEvt())
		return
	}

	// Update XFRM rules for all Child SAs (CP + UP) to use the new outer addresses.
	for _, child := range n3ueSelf.N3IWFUe.N3IWFChildSecurityAssociation {
		if child == nil {
			continue
		}

		var ifid uint32 = n3ueSelf.N3ueInfo.XfrmiId
		if len(child.XfrmStateList) > 0 && child.XfrmStateList[0].Ifid > 0 {
			ifid = uint32(child.XfrmStateList[0].Ifid) // #nosec G115
		}

		ueIsInitiator := true
		if child.SelectedIPProtocol == unix.IPPROTO_GRE {
			ueIsInitiator = false
		}

		// Remove old rules first (they refer to the previous outer IPs).
		if err := xfrm.DeleteChildSAXfrm(child); err != nil {
			ikeLog.Warnf("MOBIKE: deleting old XFRM rules failed for spi=0x%08x: %v", child.InboundSPI, err)
		}

		child.LocalPublicIPAddr = localIP
		child.PeerPublicIPAddr = peerIP
		if child.EnableEncapsulate && n3ueSelf.N3IWFUe.IKEConnection != nil &&
			n3ueSelf.N3IWFUe.IKEConnection.UEAddr != nil &&
			n3ueSelf.N3IWFUe.IKEConnection.N3IWFAddr != nil {
			child.NATPort = n3ueSelf.N3IWFUe.IKEConnection.UEAddr.Port
			child.N3IWFPort = n3ueSelf.N3IWFUe.IKEConnection.N3IWFAddr.Port
		}

		if err := xfrm.ApplyXFRMRule(ueIsInitiator, ifid, child); err != nil {
			ikeLog.Warnf("MOBIKE: applying updated XFRM rules failed for spi=0x%08x: %v", child.InboundSPI, err)
		}
	}

	// Send UPDATE_SA_ADDRESSES INFORMATIONAL to the (new) target N3IWF.
	ikeSA.InitiatorMessageID++
	var payload ike_message.IKEPayloadContainer
	payload.BuildNotification(ike_message.TypeNone, ike_message.UPDATE_SA_ADDRESSES, nil, nil)
	ikeSA.PendingMobikeUpdateMsgID = ikeSA.InitiatorMessageID

	if n3ueSelf.MobikeUpdateTimer != nil {
		n3ueSelf.MobikeUpdateTimer.Stop()
		n3ueSelf.MobikeUpdateTimer = nil
	}

	n3ueSelf.MobikeUpdateTimer = time.AfterFunc(5*time.Second, func() {
		// If there is no response, fall back to the existing break-before-make logic.
		if ikeSA.PendingMobikeUpdateMsgID != 0 {
			logger.IKELog.Warn("MOBIKE update timed out; falling back to IKE re-establishment")
			s.SendIkeEvt(context.NewStartIkeSaEstablishmentEvt())
		}
	})

	ikeLog.Infof("Sending MOBIKE UPDATE_SA_ADDRESSES msgID=%d to %s",
		ikeSA.PendingMobikeUpdateMsgID, n3ueSelf.N3IWFUe.IKEConnection.N3IWFAddr)
	s.SendN3iwfInformationExchange(n3ueSelf, &payload, true, false, ikeSA.InitiatorMessageID)
}

// stopContinuousIkeSaInit stops the continuous IKE_SA_INIT timer
func (s *Server) stopContinuousIkeSaInit() {
	n3ueContext := s.Context()
	if n3ueContext.ContinuousIkeSaInitTimer != nil {
		n3ueContext.ContinuousIkeSaInitTimer.Stop()
		n3ueContext.ContinuousIkeSaInitTimer = nil
	}
}

func (s *Server) handleIKESAINIT(
	evt *context.HandleIkeMsgSaInitEvt,
) {
	ikeLog := logger.IKELog
	ikeLog.Infoln("Handle IKESA INIT")

	udpConnInfo := evt.UdpConnInfo
	ueAddr := udpConnInfo.UEAddr
	n3iwfAddr := udpConnInfo.N3IWFAddr
	message := evt.IkeMsg
	// packet := evt.Packet

	n3ueSelf := s.Context()
	var sharedKeyExchangeData []byte
	var remoteNonce []byte
	var notifications []*ike_message.Notification
	// For NAT-T
	var ueIsBehindNAT, n3iwfIsBehindNAT bool
	var err error

	for _, ikePayload := range message.Payloads {
		switch ikePayload.Type() {
		case ike_message.TypeSA:
			ikeLog.Info("Get SA payload")
		case ike_message.TypeKE:
			remotePublicKeyExchangeValue := ikePayload.(*ike_message.KeyExchange).KeyExchangeData
			var i int = 0
			for {
				if remotePublicKeyExchangeValue[i] != 0 {
					break
				}
			}
			remotePublicKeyExchangeValue = remotePublicKeyExchangeValue[i:]
			remotePublicKeyExchangeValueBig := new(big.Int).SetBytes(remotePublicKeyExchangeValue)
			sharedKeyExchangeData = new(
				big.Int,
			).Exp(remotePublicKeyExchangeValueBig, n3ueSelf.Secert, n3ueSelf.Factor).
				Bytes()
		case ike_message.TypeNiNr:
			remoteNonce = ikePayload.(*ike_message.Nonce).NonceData
		case ike_message.TypeN:
			notifications = append(notifications, ikePayload.(*ike_message.Notification))
		}
	}

	if len(notifications) != 0 {
		ueIsBehindNAT, n3iwfIsBehindNAT, err = HandleNATDetect(
			message.InitiatorSPI, message.ResponderSPI,
			notifications, ueAddr, n3iwfAddr)
		if err != nil {
			ikeLog.Errorf("Handle IKE_SA_INIT: %v", err)
			return
		}
	}

	ikeSecurityAssociation := &context.IKESecurityAssociation{
		LocalSPI:           n3ueSelf.IkeInitiatorSPI,
		RemoteSPI:          message.ResponderSPI,
		InitiatorMessageID: 0,
		ResponderMessageID: 0,
		IKESAKey: &ike_security.IKESAKey{
			EncrInfo:  encr.DecodeTransform(n3ueSelf.Proposal.EncryptionAlgorithm[0]),
			IntegInfo: integ.DecodeTransform(n3ueSelf.Proposal.IntegrityAlgorithm[0]),
			PrfInfo:   prf.DecodeTransform(n3ueSelf.Proposal.PseudorandomFunction[0]),
			DhInfo:    dh.DecodeTransform(n3ueSelf.Proposal.DiffieHellmanGroup[0]),
		},
		NonceInitiator: n3ueSelf.LocalNonce,
		NonceResponder: remoteNonce,
		ResponderSignedOctets: append(n3ueSelf.N3IWFUe.N3IWFIKESecurityAssociation.
			ResponderSignedOctets, remoteNonce...),
		UEIsBehindNAT:     ueIsBehindNAT,
		N3IWFIsBehindNAT:  n3iwfIsBehindNAT,
		ReqRetransmitInfo: &context.ReqRetransmitInfo{},
		RspRetransmitInfo: &context.RspRetransmitInfo{},
	}
	ConcatenatedNonce := append(ikeSecurityAssociation.NonceInitiator, ikeSecurityAssociation.NonceResponder...)

	err = ikeSecurityAssociation.IKESAKey.GenerateKeyForIKESA(ConcatenatedNonce,
		sharedKeyExchangeData, ikeSecurityAssociation.LocalSPI, ikeSecurityAssociation.RemoteSPI)
	if err != nil {
		ikeLog.Errorf("Generate key for IKE SA failed: %+v", err)
		return
	}

	ikeLog.Tracef("%v", ikeSecurityAssociation.String())
	n3ueSelf.N3IWFUe.N3IWFIKESecurityAssociation = ikeSecurityAssociation

	// Stop continuous IKE_SA_INIT timer as IKE SA is now established
	s.stopContinuousIkeSaInit()

	s.SendIkeAuth()
}

func (s *Server) handleIKEAUTH(
	evt *context.HandleIkeMsgAuthEvt,
) {
	ikeLog := logger.IKELog
	ikeLog.Infoln("Handle IKE AUTH")

	udpConnInfo := evt.UdpConnInfo
	ueAddr := udpConnInfo.UEAddr
	n3iwfAddr := udpConnInfo.N3IWFAddr
	message := evt.IkeMsg

	n3ueSelf := s.Context()
	ikeSecurityAssociation := n3ueSelf.N3IWFUe.N3IWFIKESecurityAssociation
	ue := n3ueSelf.RanUeContext

	var ikePayload ike_message.IKEPayloadContainer

	// var eapIdentifier uint8
	var eapReq *ike_message.PayloadEap

	// AUTH, SAr2, TSi, Tsr, N(NAS_IP_ADDRESS), N(NAS_TCP_PORT)
	var responseSecurityAssociation *ike_message.SecurityAssociation
	var responseTrafficSelectorInitiator *ike_message.TrafficSelectorInitiator
	var responseTrafficSelectorResponder *ike_message.TrafficSelectorResponder
	var responseConfiguration *ike_message.Configuration
	receivedAuthFailure := false
	var err error
	var ok bool
	n3ueSelf.N3iwfNASAddr = new(net.TCPAddr)

	for _, ikePayload := range message.Payloads {
		switch ikePayload.Type() {
		case ike_message.TypeIDr:
			ikeLog.Info("Get IDr")
		case ike_message.TypeAUTH:
			ikeLog.Info("Get AUTH")
		case ike_message.TypeSA:
			responseSecurityAssociation = ikePayload.(*ike_message.SecurityAssociation)
			ikeSecurityAssociation.IKEAuthResponseSA = responseSecurityAssociation
		case ike_message.TypeTSi:
			responseTrafficSelectorInitiator = ikePayload.(*ike_message.TrafficSelectorInitiator)
		case ike_message.TypeTSr:
			responseTrafficSelectorResponder = ikePayload.(*ike_message.TrafficSelectorResponder)
		case ike_message.TypeCERT:
			ikeLog.Info("Get CERT")
		case ike_message.TypeN:
			notification := ikePayload.(*ike_message.Notification)
			if notification.ProtocolID == ike_message.TypeNone &&
				notification.NotifyMessageType == ike_message.MOBIKE_SUPPORTED {
				ikeSecurityAssociation.MobikeSupported = true
			}
			if notification.NotifyMessageType == ike_message.Vendor3GPPNotifyTypeNAS_IP4_ADDRESS {
				n3ueSelf.N3iwfNASAddr.IP = net.IPv4(
					notification.NotificationData[0],
					notification.NotificationData[1],
					notification.NotificationData[2],
					notification.NotificationData[3],
				)
			}
			if notification.NotifyMessageType == ike_message.Vendor3GPPNotifyTypeNAS_TCP_PORT {
				n3ueSelf.N3iwfNASAddr.Port = int(
					binary.BigEndian.Uint16(notification.NotificationData),
				)
			}
			if notification.NotifyMessageType == ike_message.AUTHENTICATION_FAILED {
				receivedAuthFailure = true
			}
		case ike_message.TypeCP:
			responseConfiguration = ikePayload.(*ike_message.Configuration)
			if responseConfiguration.ConfigurationType == ike_message.CFG_REPLY {
				n3ueSelf.UEInnerAddr = new(net.IPNet)
				for _, configAttr := range responseConfiguration.ConfigurationAttribute {
					if configAttr.Type == ike_message.INTERNAL_IP4_ADDRESS {
						n3ueSelf.UEInnerAddr.IP = configAttr.Value
					}
					if configAttr.Type == ike_message.INTERNAL_IP4_NETMASK {
						n3ueSelf.UEInnerAddr.Mask = configAttr.Value
					}
				}
			}
		case ike_message.TypeEAP:
			ikeLog.Info("Get EAP")
			eapReq = ikePayload.(*ike_message.PayloadEap)
		}
	}

	handoverActive := isHandoverActive(n3ueSelf)

	// In handover mode the target may complete EAP locally and reply with Success
	if handoverActive && eapReq != nil && eapReq.Code == ike_eap.EapCodeSuccess {
		if err := s.respondWithEapSuccess(&ikePayload, ikeSecurityAssociation, ue, n3ueSelf); err != nil {
			ikeLog.Errorf("HandleIKEAUTH() handover EAP Success: %v", err)
		}
		return
	}

	switch ikeSecurityAssociation.State {
	case IKEAUTH_Request:
		eapIdentifier := eapReq.Identifier

		// IKE_AUTH - EAP exchange
		ikeSecurityAssociation.InitiatorMessageID++

		// EAP-5G vendor type data
		eapVendorTypeData := make([]byte, 2)
		eapVendorTypeData[0] = ike_message.EAP5GType5GNAS

		// AN Parameters
		anParameters := s.BuildEAP5GANParameters()
		anParametersLength := make([]byte, 2)
		binary.BigEndian.PutUint16(anParametersLength, uint16(len(anParameters)))
		eapVendorTypeData = append(eapVendorTypeData, anParametersLength...)
		eapVendorTypeData = append(eapVendorTypeData, anParameters...)

		// NAS
		n3ueSelf.UESecurityCapability = n3ueSelf.RanUeContext.GetUESecurityCapability()

		registrationType := nasMessage.RegistrationType5GSInitialRegistration
		if handoverActive {
			registrationType = nasMessage.RegistrationType5GSMobilityRegistrationUpdating
		}
		mobileIdentity := selectMobileIdentity5GS(n3ueSelf, handoverActive)
		var capability5GMM *nasType.Capability5GMM
		if ue != nil {
			capability5GMM = ue.Get5GMMCapability()
		}
		registrationRequest := nasPacket.GetRegistrationRequest(
			registrationType,
			mobileIdentity,
			nil,
			n3ueSelf.UESecurityCapability,
			capability5GMM,
			nil,
			nil,
		)

		// For mobility registration update, protect the Registration Request if we already have a NAS security context.
		if handoverActive && ue != nil {
			if protected, encErr := ngapPacket.EncodeNasPduWithSecurity(
				ue,
				registrationRequest,
				nas.SecurityHeaderTypeIntegrityProtectedAndCiphered,
				true,
				false,
			); encErr == nil {
				registrationRequest = protected
				n3ueSelf.NeedMobilityRegUpdate = false
			} else {
				ikeLog.Warnf("Failed to protect mobility Registration Request NAS: %+v", encErr)
			}
		} else if handoverActive {
			// If we are in handover but cannot protect here, still avoid duplicating later if it gets accepted.
			n3ueSelf.NeedMobilityRegUpdate = false
		}

		nasLength := make([]byte, 2)
		binary.BigEndian.PutUint16(nasLength, uint16(len(registrationRequest)))
		eapVendorTypeData = append(eapVendorTypeData, nasLength...)
		eapVendorTypeData = append(eapVendorTypeData, registrationRequest...)

		eap := ikePayload.BuildEAP(ike_eap.EapCodeResponse, eapIdentifier)
		eap.EapTypeData = ike_message.BuildEapExpanded(
			ike_eap.VendorId3GPP,
			ike_eap.VendorTypeEAP5G,
			eapVendorTypeData,
		)

		ikeMessage := ike_message.NewMessage(
			ikeSecurityAssociation.LocalSPI,
			ikeSecurityAssociation.RemoteSPI,
			ike_message.IKE_AUTH,
			false, true,
			ikeSecurityAssociation.InitiatorMessageID,
			ikePayload,
		)

		err = s.SendIkeMsgToN3iwf(
			n3ueSelf.N3IWFUe.IKEConnection,
			ikeMessage,
			ikeSecurityAssociation,
		)
		if err != nil {
			ikeLog.Errorf("HandleIKEAUTH() IKEAUTH_Request: %v", err)
			return
		}

		// TS 33.102
		// Sync the SQN for security in config
		if err = factory.SyncConfigSQN(1); err != nil {
			ikeLog.Errorf("syncConfigSQN: %+v", err)
			return
		}
		ikeSecurityAssociation.State++

	case EAP_RegistrationRequest:
		var eapExpanded *ike_eap.EapExpanded
		eapExpanded, ok = eapReq.EapTypeData.(*ike_eap.EapExpanded)
		if !ok {
			ikeLog.Error("The EAP data is not an EAP expended.")
			return
		}

		var decodedNAS *nas.Message

		// Decode NAS - Authentication Request
		nasData := eapExpanded.VendorData[4:]
		decodedNAS = new(nas.Message)
		if err = decodedNAS.PlainNasDecode(&nasData); err != nil {
			ikeLog.Errorf("Decode plain NAS fail: %+v", err)
			return
		}

		// Calculate for RES*
		if decodedNAS.GmmMessage == nil {
			nasLog.Error("decodedNAS is nil")
			return
		}

		switch decodedNAS.GmmMessage.GetMessageType() {
		case nas.MsgTypeAuthenticationRequest:
			nasLog.Info("Received Authentication Request")
		default:
			nasLog.Errorf("Received unexpected message type: %d",
				decodedNAS.GmmMessage.GetMessageType())
		}

		rand := decodedNAS.AuthenticationRequest.GetRANDValue()

		snn := n3ueSelf.N3ueInfo.GetSNN()
		nasLog.Infof("SNN: %+v", snn)
		resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], snn)

		nasLog.Infof("KnasEnc: %0x", ue.KnasEnc)
		nasLog.Infof("KnasInt: %0x", ue.KnasInt)
		nasLog.Infof("Kamf: %0x", ue.Kamf)
		nasLog.Infof("AnType: %s", ue.AnType)
		nasLog.Infof("SUPI: %s", ue.Supi)

		// send NAS Authentication Response
		pdu := nasPacket.GetAuthenticationResponse(resStat, "")

		// IKE_AUTH - EAP exchange
		ikeSecurityAssociation.InitiatorMessageID++

		// EAP-5G vendor type data
		eapVendorTypeData := make([]byte, 4)
		eapVendorTypeData[0] = ike_message.EAP5GType5GNAS

		// NAS - Authentication Response
		nasLength := make([]byte, 2)
		binary.BigEndian.PutUint16(nasLength, uint16(len(pdu)))
		eapVendorTypeData = append(eapVendorTypeData, nasLength...)
		eapVendorTypeData = append(eapVendorTypeData, pdu...)

		eap := ikePayload.BuildEAP(ike_eap.EapCodeResponse, eapReq.Identifier)
		eap.EapTypeData = ike_message.BuildEapExpanded(
			ike_eap.VendorId3GPP,
			ike_eap.VendorTypeEAP5G,
			eapVendorTypeData,
		)

		ikeMessage := ike_message.NewMessage(
			ikeSecurityAssociation.LocalSPI,
			ikeSecurityAssociation.RemoteSPI,
			ike_message.IKE_AUTH,
			false, true,
			ikeSecurityAssociation.InitiatorMessageID,
			ikePayload,
		)

		err = s.SendIkeMsgToN3iwf(
			n3ueSelf.N3IWFUe.IKEConnection,
			ikeMessage,
			ikeSecurityAssociation,
		)
		if err != nil {
			ikeLog.Errorf("HandleIKEAUTH() EAP_RegistrationRequest: %v", err)
			return
		}

		ikeSecurityAssociation.State++
	case EAP_Authentication:
		_, ok = eapReq.EapTypeData.(*ike_eap.EapExpanded)
		if !ok {
			ikeLog.Error("The EAP data is not an EAP expended.")
			return
		}
		// nasData := eapExpanded.VendorData[4:]

		// Send NAS Security Mode Complete Msg
		registrationType := nasMessage.RegistrationType5GSInitialRegistration
		if handoverActive {
			registrationType = nasMessage.RegistrationType5GSMobilityRegistrationUpdating
		}
		mobileIdentity := selectMobileIdentity5GS(n3ueSelf, handoverActive)
		registrationRequestWith5GMM := nasPacket.GetRegistrationRequest(
			registrationType,
			mobileIdentity,
			nil,
			n3ueSelf.UESecurityCapability,
			ue.Get5GMMCapability(),
			nil,
			nil,
		)
		pdu := nasPacket.GetSecurityModeComplete(registrationRequestWith5GMM)
		if pdu, err = ngapPacket.EncodeNasPduWithSecurity(ue,
			pdu,
			nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext,
			true,
			true); err != nil {
			nasLog.Errorf("EncodeNasPduWithSecurity: %+v", err)
			return
		}

		// IKE_AUTH - EAP exchange
		ikeSecurityAssociation.InitiatorMessageID++

		// EAP-5G vendor type data
		eapVendorTypeData := make([]byte, 4)
		eapVendorTypeData[0] = ike_message.EAP5GType5GNAS

		// NAS - Authentication Response
		nasLength := make([]byte, 2)
		binary.BigEndian.PutUint16(nasLength, uint16(len(pdu)))
		eapVendorTypeData = append(eapVendorTypeData, nasLength...)
		eapVendorTypeData = append(eapVendorTypeData, pdu...)

		eap := ikePayload.BuildEAP(ike_eap.EapCodeResponse, eapReq.Identifier)
		eap.EapTypeData = ike_message.BuildEapExpanded(
			ike_eap.VendorId3GPP,
			ike_eap.VendorTypeEAP5G,
			eapVendorTypeData,
		)

		ikeMessage := ike_message.NewMessage(
			ikeSecurityAssociation.LocalSPI,
			ikeSecurityAssociation.RemoteSPI,
			ike_message.IKE_AUTH,
			false, true,
			ikeSecurityAssociation.InitiatorMessageID,
			ikePayload,
		)

		err = s.SendIkeMsgToN3iwf(
			n3ueSelf.N3IWFUe.IKEConnection,
			ikeMessage,
			ikeSecurityAssociation,
		)
		if err != nil {
			ikeLog.Errorf("HandleIKEAUTH() EAP_Authentication: %v", err)
			return
		}

		ikeSecurityAssociation.State++
	case EAP_NASSecurityComplete:
		if eapReq.Code != ike_eap.EapCodeSuccess {
			ikeLog.Error("Not Success")
			return
		}
		if err := s.respondWithEapSuccess(&ikePayload, ikeSecurityAssociation, ue, n3ueSelf); err != nil {
			ikeLog.Errorf("HandleIKEAUTH() EAP_NASSecurityComplete: %v", err)
		}
	case IKEAUTH_Authentication:
		if receivedAuthFailure {
			ikeLog.Error("IKE_AUTH authentication failed (received AUTHENTICATION_FAILED notify from N3IWF)")
			return
		}
		if ikeSecurityAssociation.IKEAuthResponseSA == nil ||
			len(ikeSecurityAssociation.IKEAuthResponseSA.Proposals) == 0 ||
			len(ikeSecurityAssociation.IKEAuthResponseSA.Proposals[0].SPI) < 4 {
			ikeLog.Error("IKE_AUTH response missing Child-SA (SA/Proposal/SPI), cannot complete Child SA")
			return
		}
		if responseTrafficSelectorInitiator == nil || responseTrafficSelectorResponder == nil ||
			len(responseTrafficSelectorInitiator.TrafficSelectors) == 0 ||
			len(responseTrafficSelectorResponder.TrafficSelectors) == 0 {
			ikeLog.Error("IKE_AUTH response missing Traffic Selectors, cannot complete Child SA")
			return
		}
		// Get outbound SPI from proposal provided by N3IWF
		OutboundSPI := binary.BigEndian.Uint32(
			ikeSecurityAssociation.IKEAuthResponseSA.Proposals[0].SPI,
		)
		childSecurityAssociationContext, err := n3ueSelf.N3IWFUe.CompleteChildSA(
			0x01, OutboundSPI, ikeSecurityAssociation.IKEAuthResponseSA)
		if err != nil {
			ikeLog.Errorf("Create child security association context failed: %+v", err)
			return
		}
		err = ParseIPAddressInformationToChildSecurityAssociation(
			childSecurityAssociationContext,
			responseTrafficSelectorInitiator.TrafficSelectors[0],
			responseTrafficSelectorResponder.TrafficSelectors[0])
		if err != nil {
			ikeLog.Errorf("Parse IP address to child security association failed: %+v", err)
			return
		}
		// Select TCP traffic
		childSecurityAssociationContext.SelectedIPProtocol = unix.IPPROTO_TCP
		childSecurityAssociationContext.NonceInitiator = ikeSecurityAssociation.NonceInitiator
		childSecurityAssociationContext.NonceResponder = ikeSecurityAssociation.NonceResponder
		concatenatedNonce := append(childSecurityAssociationContext.NonceInitiator,
			childSecurityAssociationContext.NonceResponder...)

		err = childSecurityAssociationContext.GenerateKeyForChildSA(ikeSecurityAssociation.IKESAKey,
			concatenatedNonce)
		if err != nil {
			ikeLog.Errorf("HandleIKEAUTH Generate key for child SA failed: %+v", err)
			return
		}

		// ====== Inbound ======
		ikeLog.Debugln("====== IPSec/Child SA for 3GPP CP Inbound =====")
		ikeLog.Debugf(
			"[UE:%+v] <- [N3IWF:%+v]",
			childSecurityAssociationContext.LocalPublicIPAddr,
			childSecurityAssociationContext.PeerPublicIPAddr,
		)
		ikeLog.Debugf("IPSec SPI: 0x%016x", childSecurityAssociationContext.InboundSPI)
		ikeLog.Debugf(
			"IPSec Encryption Algorithm: %d",
			childSecurityAssociationContext.EncrKInfo.TransformID(),
		)
		ikeLog.Debugf(
			"IPSec Encryption Key: 0x%x",
			childSecurityAssociationContext.ResponderToInitiatorEncryptionKey,
		)
		ikeLog.Debugf(
			"IPSec Integrity  Algorithm: %d",
			childSecurityAssociationContext.IntegKInfo.TransformID(),
		)
		ikeLog.Debugf(
			"IPSec Integrity  Key: 0x%x",
			childSecurityAssociationContext.ResponderToInitiatorIntegrityKey,
		)
		// ====== Outbound ======
		ikeLog.Debugln("====== IPSec/Child SA for 3GPP CP Outbound =====")
		ikeLog.Debugf(
			"[UE:%+v] -> [N3IWF:%+v]",
			childSecurityAssociationContext.LocalPublicIPAddr,
			childSecurityAssociationContext.PeerPublicIPAddr,
		)
		ikeLog.Debugf("IPSec SPI: 0x%016x", childSecurityAssociationContext.OutboundSPI)
		ikeLog.Debugf(
			"IPSec Encryption Algorithm: %d",
			childSecurityAssociationContext.EncrKInfo.TransformID(),
		)
		ikeLog.Debugf(
			"IPSec Encryption Key: 0x%x",
			childSecurityAssociationContext.InitiatorToResponderEncryptionKey,
		)
		ikeLog.Debugf(
			"IPSec Integrity  Algorithm: %d",
			childSecurityAssociationContext.IntegKInfo.TransformID(),
		)
		ikeLog.Debugf(
			"IPSec Integrity  Key: 0x%x",
			childSecurityAssociationContext.InitiatorToResponderIntegrityKey,
		)

		// NAT-T concern
		if ikeSecurityAssociation.UEIsBehindNAT || ikeSecurityAssociation.N3IWFIsBehindNAT {
			childSecurityAssociationContext.EnableEncapsulate = true
			childSecurityAssociationContext.N3IWFPort = n3iwfAddr.Port
			childSecurityAssociationContext.NATPort = ueAddr.Port
		}

		// Setup interface for ipsec
		newXfrmiName := fmt.Sprintf("%s-%d", n3ueSelf.N3ueInfo.XfrmiName, n3ueSelf.N3ueInfo.XfrmiId)
		if _, err = xfrm.SetupIPsecXfrmi(newXfrmiName,
			n3ueSelf.N3ueInfo.IPSecIfaceName,
			n3ueSelf.N3ueInfo.XfrmiId,
			n3ueSelf.UEInnerAddr); err != nil {
			ikeLog.Errorf("Setup XFRM interface %s fail: %+v", newXfrmiName, err)
			return
		}

		// Aplly XFRM rules
		if err = xfrm.ApplyXFRMRule(true, n3ueSelf.N3ueInfo.XfrmiId, childSecurityAssociationContext); err != nil {
			ikeLog.Errorf("Applying XFRM rules failed: %+v", err)
			return
		}

		s.StartInboundMessageTimer(ikeSecurityAssociation)

		s.cancelHandoverFallbackTimer()
		s.SendProcedureEvt(context.NewNwucpChildSaCreatedEvt())
	}
}

func (s *Server) handleCREATECHILDSA(
	evt *context.HandleIkeMsgCreateChildSaEvt,
) {
	ikeLog := logger.IKELog
	ikeLog.Tracef("Handle CreateChildSA")

	udpConnInfo := evt.UdpConnInfo
	ueAddr := udpConnInfo.UEAddr
	n3iwfAddr := udpConnInfo.N3IWFAddr
	message := evt.IkeMsg

	n3ueSelf := s.Context()
	ikeSecurityAssociation := n3ueSelf.N3IWFUe.N3IWFIKESecurityAssociation
	ikeSecurityAssociation.ResponderMessageID = message.MessageID

	var ikePayload ike_message.IKEPayloadContainer

	var QoSInfo *qos.PDUQoSInfo
	var OutboundSPI uint32
	// AUTH, SAr2, TSi, Tsr, N(NAS_IP_ADDRESS), N(NAS_TCP_PORT)
	var responseSecurityAssociation *ike_message.SecurityAssociation
	var responseTrafficSelectorInitiator *ike_message.TrafficSelectorInitiator
	var responseTrafficSelectorResponder *ike_message.TrafficSelectorResponder
	var err error
	var nonce []byte

	for _, ikePayload := range message.Payloads {
		switch ikePayload.Type() {
		case ike_message.TypeSA:
			responseSecurityAssociation = ikePayload.(*ike_message.SecurityAssociation)
			OutboundSPI = binary.BigEndian.Uint32(responseSecurityAssociation.Proposals[0].SPI)
		case ike_message.TypeTSi:
			responseTrafficSelectorInitiator = ikePayload.(*ike_message.TrafficSelectorInitiator)
		case ike_message.TypeTSr:
			responseTrafficSelectorResponder = ikePayload.(*ike_message.TrafficSelectorResponder)
		case ike_message.TypeN:
			notification := ikePayload.(*ike_message.Notification)
			if notification.NotifyMessageType == ike_message.Vendor3GPPNotifyType5G_QOS_INFO {
				ikeLog.Info("Received Qos Flow settings")
				var info *qos.PDUQoSInfo
				if info, err = qos.Parse5GQoSInfoNotify(notification); err == nil {
					QoSInfo = info
					ikeLog.Infof("NotificationData:%+v", notification.NotificationData)
					if QoSInfo.IsDSCPSpecified {
						ikeLog.Infof("DSCP is specified but test not support")
					}
				} else {
					ikeLog.Infof("%+v", err)
				}
				n3ueSelf.TemporaryQosInfo = QoSInfo
			}
			if notification.NotifyMessageType == ike_message.Vendor3GPPNotifyTypeUP_IP4_ADDRESS {
				n3ueSelf.TemporaryUPIPAddr = notification.NotificationData[:4]
				ikeLog.Infof("UP IP Address: %+v\n", n3ueSelf.TemporaryUPIPAddr)
			}
		case ike_message.TypeNiNr:
			responseNonce := ikePayload.(*ike_message.Nonce)
			nonce = responseNonce.NonceData
		}
	}

	// SA
	inboundSPI, err := GenerateSPI(n3ueSelf.N3IWFUe)
	if err != nil {
		ikeLog.Errorf("HandleCREATECHILDSA(): %v", err)
	}
	ikeLog.Tracef("inboundspi : %+v", inboundSPI)
	responseSecurityAssociation.Proposals[0].SPI = inboundSPI
	ikePayload = append(ikePayload, responseSecurityAssociation)

	// TSi
	ikePayload = append(ikePayload, responseTrafficSelectorInitiator)

	// TSr
	ikePayload = append(ikePayload, responseTrafficSelectorResponder)

	// Nonce
	localNonceBigInt, err := ike_security.GenerateRandomNumber()
	if err != nil {
		ikeLog.Errorf("HandleCREATECHILDSA(): %v", err)
		return
	}
	localNonce := localNonceBigInt.Bytes()
	ikePayload.BuildNonce(localNonce)

	ikeMessage := ike_message.NewMessage(
		ikeSecurityAssociation.LocalSPI,
		ikeSecurityAssociation.RemoteSPI,
		ike_message.CREATE_CHILD_SA,
		true, true,
		ikeSecurityAssociation.ResponderMessageID,
		ikePayload,
	)

	err = s.SendIkeMsgToN3iwf(
		n3ueSelf.N3IWFUe.IKEConnection,
		ikeMessage,
		ikeSecurityAssociation,
	)
	if err != nil {
		ikeLog.Errorf("HandleCREATECHILDSA(): %v", err)
		return
	}

	n3ueSelf.N3IWFUe.CreateHalfChildSA(
		ikeSecurityAssociation.ResponderMessageID,
		binary.BigEndian.Uint32(inboundSPI),
		-1,
	)
	childSecurityAssociationContextUserPlane, err := n3ueSelf.N3IWFUe.CompleteChildSA(
		ikeSecurityAssociation.ResponderMessageID, OutboundSPI, responseSecurityAssociation)
	if err != nil {
		ikeLog.Errorf("Create child security association context failed: %+v", err)
		return
	}

	err = ParseIPAddressInformationToChildSecurityAssociation(
		childSecurityAssociationContextUserPlane,
		responseTrafficSelectorResponder.TrafficSelectors[0],
		responseTrafficSelectorInitiator.TrafficSelectors[0])
	if err != nil {
		ikeLog.Errorf("Parse IP address to child security association failed: %+v", err)
		return
	}
	// Select GRE traffic
	childSecurityAssociationContextUserPlane.SelectedIPProtocol = unix.IPPROTO_GRE
	childSecurityAssociationContextUserPlane.NonceInitiator = nonce
	childSecurityAssociationContextUserPlane.NonceResponder = localNonce
	concatenatedNonce := append(childSecurityAssociationContextUserPlane.NonceInitiator,
		childSecurityAssociationContextUserPlane.NonceResponder...)

	err = childSecurityAssociationContextUserPlane.GenerateKeyForChildSA(ikeSecurityAssociation.IKESAKey,
		concatenatedNonce)
	if err != nil {
		ikeLog.Errorf("HandleCREATECHILDSA() Generate key for child SA failed: %+v", err)
		return
	}

	// NAT-T concern
	if ikeSecurityAssociation.UEIsBehindNAT || ikeSecurityAssociation.N3IWFIsBehindNAT {
		childSecurityAssociationContextUserPlane.EnableEncapsulate = true
		childSecurityAssociationContextUserPlane.N3IWFPort = n3iwfAddr.Port
		childSecurityAssociationContextUserPlane.NATPort = ueAddr.Port
	}

	n3ueSelf.N3ueInfo.XfrmiId++
	// Aplly XFRM rules
	if err = xfrm.ApplyXFRMRule(false, n3ueSelf.N3ueInfo.XfrmiId, childSecurityAssociationContextUserPlane); err != nil {
		ikeLog.Errorf("Applying XFRM rules failed: %+v", err)
		return
	}

	// ====== Inbound ======
	ikeLog.Debugln("====== IPSec/Child SA for 3GPP UP Inbound =====")
	ikeLog.Debugf(
		"[UE:%+v] <- [N3IWF:%+v]",
		childSecurityAssociationContextUserPlane.LocalPublicIPAddr,
		childSecurityAssociationContextUserPlane.PeerPublicIPAddr,
	)
	ikeLog.Debugf("IPSec SPI: 0x%016x", childSecurityAssociationContextUserPlane.InboundSPI)
	ikeLog.Debugf(
		"IPSec Encryption Algorithm: %d",
		childSecurityAssociationContextUserPlane.EncrKInfo.TransformID(),
	)
	ikeLog.Debugf(
		"IPSec Encryption Key: 0x%x",
		childSecurityAssociationContextUserPlane.InitiatorToResponderEncryptionKey,
	)
	ikeLog.Debugf(
		"IPSec Integrity  Algorithm: %d",
		childSecurityAssociationContextUserPlane.IntegKInfo.TransformID(),
	)
	ikeLog.Debugf(
		"IPSec Integrity  Key: 0x%x",
		childSecurityAssociationContextUserPlane.InitiatorToResponderIntegrityKey,
	)
	// ====== Outbound ======
	ikeLog.Debugln("====== IPSec/Child SA for 3GPP UP Outbound =====")
	ikeLog.Debugf(
		"[UE:%+v] -> [N3IWF:%+v]",
		childSecurityAssociationContextUserPlane.LocalPublicIPAddr,
		childSecurityAssociationContextUserPlane.PeerPublicIPAddr,
	)
	ikeLog.Debugf("IPSec SPI: 0x%016x", childSecurityAssociationContextUserPlane.OutboundSPI)
	ikeLog.Debugf(
		"IPSec Encryption Algorithm: %d",
		childSecurityAssociationContextUserPlane.EncrKInfo.TransformID(),
	)
	ikeLog.Debugf(
		"IPSec Encryption Key: 0x%x",
		childSecurityAssociationContextUserPlane.ResponderToInitiatorEncryptionKey,
	)
	ikeLog.Debugf(
		"IPSec Integrity  Algorithm: %d",
		childSecurityAssociationContextUserPlane.IntegKInfo.TransformID(),
	)
	ikeLog.Debugf(
		"IPSec Integrity  Key: 0x%x",
		childSecurityAssociationContextUserPlane.ResponderToInitiatorIntegrityKey,
	)
	ikeLog.Debugf(
		"State function: encr: %d, auth: %d",
		childSecurityAssociationContextUserPlane.EncrKInfo.TransformID(),
		childSecurityAssociationContextUserPlane.IntegKInfo.TransformID(),
	)

	// Setup interface for ipsec
	n3ueSelf.TemporaryXfrmiName = fmt.Sprintf(
		"%s-%d",
		n3ueSelf.N3ueInfo.XfrmiName,
		n3ueSelf.N3ueInfo.XfrmiId,
	)
	if _, err = xfrm.SetupIPsecXfrmi(n3ueSelf.TemporaryXfrmiName, n3ueSelf.N3ueInfo.IPSecIfaceName,
		n3ueSelf.N3ueInfo.XfrmiId, n3ueSelf.UEInnerAddr); err != nil {
		ikeLog.Errorf("Setup XFRMi interface %s fail: %+v", n3ueSelf.TemporaryXfrmiName, err)
	}
	ikeLog.Infof("Setup XFRM interface %s successfully", n3ueSelf.TemporaryXfrmiName)
}

func (s *Server) handleInformational(
	evt *context.HandleIkeMsgInformationalEvt,
) {
	ikeLog := logger.IKELog
	ikeLog.Infof("Handle Informational: msgID=%d isResponse=%t payloads=%d",
		evt.IkeMsg.IKEHeader.MessageID, evt.IkeMsg.IsResponse(), len(evt.IkeMsg.Payloads))

	message := evt.IkeMsg

	n3ueSelf := s.Context()
	ikeSA := n3ueSelf.N3IWFUe.N3IWFIKESecurityAssociation

	// Handle responses to our own INFORMATIONAL requests (DPD, MOBIKE, etc.).
	if message.IsResponse() {
		if ikeSA != nil && ikeSA.PendingMobikeUpdateMsgID != 0 && message.IKEHeader.MessageID == ikeSA.PendingMobikeUpdateMsgID {
			ikeLog.Infof("MOBIKE UPDATE_SA_ADDRESSES acknowledged (msgID=%d)", ikeSA.PendingMobikeUpdateMsgID)
			ikeSA.PendingMobikeUpdateMsgID = 0
			if n3ueSelf.MobikeUpdateTimer != nil {
				n3ueSelf.MobikeUpdateTimer.Stop()
				n3ueSelf.MobikeUpdateTimer = nil
			}

			// Mark handover as completed from the IPSec perspective.
			if n3ueSelf.PendingHandover != nil {
				n3ueSelf.PendingHandover = nil
				n3ueSelf.NeedMobilityRegUpdate = false
			}
		}
		return
	}

	var deletePayload *ike_message.Delete
	var targetToSourceNotify []byte
	var responsePayload *ike_message.IKEPayloadContainer
	var handoverCtx *context.HandoverExecutionContext

	for idx, ikePayload := range message.Payloads {
		switch ikePayload.Type() {
		case ike_message.TypeD:
			deletePayload = ikePayload.(*ike_message.Delete)
			ikeLog.Infof("Informational payload[%d]: Delete proto=%d spi=%v", idx, deletePayload.ProtocolID, deletePayload.SPIs)
		case ike_message.TypeN:
			notification := ikePayload.(*ike_message.Notification)
			if notification.ProtocolID == ike_message.TypeNone &&
				notification.NotifyMessageType == targetToSourceNotifyType {
				targetToSourceNotify = append([]byte(nil), notification.NotificationData...)
			} else {
				ikeLog.Infof("Informational payload[%d]: Notify type=%d proto=%d spi=%v dataLen=%d",
					idx, notification.NotifyMessageType, notification.ProtocolID, notification.SPI, len(notification.NotificationData))
			}
		default:
			ikeLog.Warnf("Unhandled Ike payload type[%s] informational message", ikePayload.Type().String())
		}
	}

	if !message.IsResponse() {
		ikeSA.ResponderMessageID = message.MessageID
		ikeLog.Infof("Informational request from %s msgID=%d (responderMsgID now %d)",
			n3ueSelf.N3iwfInfo.IPSecIfaceAddr, message.MessageID, ikeSA.ResponderMessageID)
		if len(targetToSourceNotify) > 0 {
			payload, ctx, err := s.handleTargetToSourceNotify(targetToSourceNotify)
			if err != nil {
				ikeLog.Errorf("Handle target-to-source notify failed: %+v", err)
			}
			if payload != nil && len(*payload) > 0 {
				responsePayload = payload
			}
			if ctx != nil {
				handoverCtx = ctx
			}
		} else {
			ikeLog.Trace("No target-to-source notify present in informational")
		}
		if deletePayload != nil {
			// Allow deletion, but if handover is active keep the app alive and continue with target
			if n3ueSelf.PendingHandover != nil {
				ikeLog.Infof("Handover in progress, acknowledging delete without shutdown")
			} else {
				ikeLog.Infof("Received delete payload, sending deregistration complete event")
				s.SendProcedureEvt(context.NewDeregistrationCompleteEvt())
			}
		} else if len(targetToSourceNotify) == 0 {
			ikeLog.Tracef("Receive DPD message request")
		}
		s.SendN3iwfInformationExchange(n3ueSelf, responsePayload, true, true, message.MessageID)

		// Perform Wi-Fi switch only after acknowledging the informational request; otherwise the response may be lost.
		if handoverCtx != nil {
			if err := s.switchWifiForHandover(handoverCtx); err != nil {
				ikeLog.Errorf("Wi-Fi switch for handover failed: %+v", err)
				if n3ueSelf.PendingHandover == handoverCtx {
					n3ueSelf.PendingHandover = nil
					n3ueSelf.NeedMobilityRegUpdate = false
				}
				return
			}
			s.SendProcedureEvt(context.NewStartHandoverEvt())
		}
	}
}

func (s *Server) handleTargetToSourceNotify(
	data []byte,
) (*ike_message.IKEPayloadContainer, *context.HandoverExecutionContext, error) {
	ikeLog := logger.IKELog

	ikeLog.Infof("Received target-to-source notify (len=%d bytes)", len(data))

	container, err := parseTargetToSourceContainer(data)
	if err != nil {
		return s.buildHandoverFailurePayload("parse_error", err.Error()), nil, err
	}

	execCtx, err := buildHandoverContextFromContainer(container)
	if err != nil {
		return s.buildHandoverFailurePayload("invalid_payload", err.Error()), nil, err
	}

	ikeLog.Infof("Target-to-source notify parsed: targetIP=%s natt=%t tunnels=%d wifi_config=%t",
		execCtx.TargetN3iwfIP, execCtx.EnableNATT, len(execCtx.Tunnels), execCtx.Wifi != nil)

	for i, t := range execCtx.Tunnels {
		ikeLog.Infof("Handover tunnel[%d]: pduSessionID=%d targetIP=%s targetTEID=%d upfIP=%s gtpBindIP=%s qfi=%v",
			i, t.PDUSessionID, t.TargetIP, t.TargetTEID, t.UPFIP, t.GTPBindIP, t.QFIs)
	}

	n3ueSelf := s.Context()
	execCtx.SourceN3iwfIP = cloneIP(net.ParseIP(n3ueSelf.N3iwfInfo.IPSecIfaceAddr))
	n3ueSelf.SourceIKEEndpoints = snapshotIKEEndpoints(n3ueSelf)
	n3ueSelf.PendingHandover = execCtx
	n3ueSelf.NeedMobilityRegUpdate = true
	s.applyNasHandoverContext(execCtx.Nas)

	// Refresh DPD timestamp and timer right before handover to avoid stale dead-peer checks
	if n3ueSelf.N3IWFUe != nil && n3ueSelf.N3IWFUe.N3IWFIKESecurityAssociation != nil {
		ikeSA := n3ueSelf.N3IWFUe.N3IWFIKESecurityAssociation
		ikeSA.UpdateInboundMessageTimestamp()
		s.ResetInboundMessageTimer(ikeSA)
		ikeLog.Trace("DPD timer refreshed before handover")
	}

	ikeLog.Infof("Prepared handover context from target-to-source notify towards %s (%d tunnels)",
		execCtx.TargetN3iwfIP, len(execCtx.Tunnels))

	//s.startHandoverFallbackTimer(execCtx)
	return nil, execCtx, nil
}

func (s *Server) applyNasHandoverContext(nasCtx *context.NasHandoverContext) {
	if nasCtx == nil {
		return
	}

	n3ueSelf := s.Context()
	n3ueSelf.NasNcc = nasCtx.NCC
	if len(nasCtx.NH) > 0 {
		n3ueSelf.NasNh = append([]byte(nil), nasCtx.NH...)
	}

	if nasCtx.GUTI != "" {
		guti := nasConvert.GutiToNas(nasCtx.GUTI)
		n3ueSelf.GUTI = &guti
		if n3ueSelf.N3IWFRanUe != nil {
			n3ueSelf.N3IWFRanUe.Guti = nasCtx.GUTI
		}
	}
}

func isNasHandoverActive(n3ueSelf *context.N3UE) bool {
	if n3ueSelf == nil {
		return false
	}
	if n3ueSelf.PendingHandover == nil {
		return false
	}
	return len(n3ueSelf.NasNh) > 0
}

func isHandoverActive(n3ueSelf *context.N3UE) bool {
	return n3ueSelf != nil && n3ueSelf.PendingHandover != nil
}

func selectMobileIdentity5GS(n3ueSelf *context.N3UE, handoverActive bool) nasType.MobileIdentity5GS {
	if n3ueSelf == nil {
		return nasType.MobileIdentity5GS{}
	}

	// For mobility registration update, prefer 5G-GUTI if available.
	if handoverActive && n3ueSelf.GUTI != nil {
		buf := append([]uint8(nil), n3ueSelf.GUTI.Octet[:]...)
		return nasType.MobileIdentity5GS{
			Len:    n3ueSelf.GUTI.Len,
			Buffer: buf,
		}
	}

	return n3ueSelf.MobileIdentity5GS
}

func selectKn3iwfKeyMaterial(n3ueSelf *context.N3UE) ([]byte, string, error) {
	if n3ueSelf == nil || n3ueSelf.RanUeContext == nil {
		return nil, "", fmt.Errorf("UE security context unavailable")
	}

	if len(n3ueSelf.RanUeContext.Kamf) > 0 {
		return n3ueSelf.RanUeContext.Kamf, "Kamf", nil
	}
	if len(n3ueSelf.NasNh) > 0 {
		return n3ueSelf.NasNh, "NH", nil
	}

	return nil, "", fmt.Errorf("no key material for KN3IWF derivation")
}

func (s *Server) respondWithEapSuccess(
	ikePayload *ike_message.IKEPayloadContainer,
	ikeSecurityAssociation *context.IKESecurityAssociation,
	ue *n3ue_security.RanUeContext,
	n3ueSelf *context.N3UE,
) error {
	ikeLog := logger.IKELog
	if ikePayload == nil || ikeSecurityAssociation == nil || ue == nil || n3ueSelf == nil {
		return fmt.Errorf("missing context for EAP-Success handling")
	}

	// IKE_AUTH - Authentication
	ikeSecurityAssociation.InitiatorMessageID++

	keyMaterial, keyLabel, err := selectKn3iwfKeyMaterial(n3ueSelf)
	if err != nil {
		return err
	}

	ulCount := ue.ULCount.Get()
	if ulCount > 0 {
		ulCount--
	}

	P0 := make([]byte, 4)
	binary.BigEndian.PutUint32(P0, ulCount)
	L0 := ueauth.KDFLen(P0)
	P1 := []byte{security.AccessTypeNon3GPP}
	L1 := ueauth.KDFLen(P1)

	if n3ueSelf.Kn3iwf, err = ueauth.GetKDFValue(
		keyMaterial,
		ueauth.FC_FOR_KGNB_KN3IWF_DERIVATION,
		P0,
		L0,
		P1,
		L1,
	); err != nil {
		return fmt.Errorf("derive KN3IWF from %s: %w", keyLabel, err)
	}

	ikeLog.Debugf("Derived KN3IWF from %s (ULCount=%d NCC=%d)", keyLabel, ulCount, n3ueSelf.NasNcc)

	var idPayload ike_message.IKEPayloadContainer
	idPayload.BuildIdentificationInitiator(ike_message.ID_KEY_ID, []byte("UE"))
	idPayloadData, err := idPayload.Encode()
	if err != nil {
		return fmt.Errorf("encode IDi payload: %w", err)
	}
	if _, err = ikeSecurityAssociation.Prf_i.Write(idPayloadData[4:]); err != nil {
		return fmt.Errorf("pseudorandom function write error: %w", err)
	}
	ikeSecurityAssociation.ResponderSignedOctets = append(
		ikeSecurityAssociation.ResponderSignedOctets,
		ikeSecurityAssociation.Prf_i.Sum(nil)...)

	pseudorandomFunction := ikeSecurityAssociation.PrfInfo.Init(n3ueSelf.Kn3iwf)
	if _, err = pseudorandomFunction.Write([]byte("Key Pad for IKEv2")); err != nil {
		return fmt.Errorf("pseudorandom function write error: %w", err)
	}
	secret := pseudorandomFunction.Sum(nil)
	pseudorandomFunction = ikeSecurityAssociation.PrfInfo.Init(secret)
	pseudorandomFunction.Reset()
	if _, err = pseudorandomFunction.Write(ikeSecurityAssociation.ResponderSignedOctets); err != nil {
		return fmt.Errorf("pseudorandom function write error: %w", err)
	}
	ikePayload.BuildAuthentication(
		ike_message.SharedKeyMesageIntegrityCode,
		pseudorandomFunction.Sum(nil),
	)

	// Configuration Request
	configurationRequest := ikePayload.BuildConfiguration(ike_message.CFG_REQUEST)
	configurationRequest.ConfigurationAttribute.BuildConfigurationAttribute(
		ike_message.INTERNAL_IP4_ADDRESS,
		nil,
	)

	ikeMessage := ike_message.NewMessage(
		ikeSecurityAssociation.LocalSPI,
		ikeSecurityAssociation.RemoteSPI,
		ike_message.IKE_AUTH,
		false, true,
		ikeSecurityAssociation.InitiatorMessageID,
		*ikePayload,
	)

	if err = s.SendIkeMsgToN3iwf(
		n3ueSelf.N3IWFUe.IKEConnection,
		ikeMessage,
		ikeSecurityAssociation,
	); err != nil {
		return fmt.Errorf("send IKE_AUTH after EAP success: %w", err)
	}

	ikeSecurityAssociation.State = IKEAUTH_Authentication
	return nil
}

func HandleNATDetect(
	initiatorSPI, responderSPI uint64,
	notifications []*ike_message.Notification,
	ueAddr, n3iwfAddr *net.UDPAddr,
) (bool, bool, error) {
	ikeLog := logger.IKELog
	ueBehindNAT := false
	n3iwfBehindNAT := false

	srcNatDData, err := GenerateNATDetectHash(initiatorSPI, responderSPI, n3iwfAddr)
	if err != nil {
		return false, false, errors.Wrapf(err, "handle NATD")
	}

	dstNatDData, err := GenerateNATDetectHash(initiatorSPI, responderSPI, ueAddr)
	if err != nil {
		return false, false, errors.Wrapf(err, "handle NATD")
	}

	for _, notification := range notifications {
		switch notification.NotifyMessageType {
		case ike_message.NAT_DETECTION_SOURCE_IP:
			ikeLog.Tracef("Received IKE Notify: NAT_DETECTION_SOURCE_IP")
			if !bytes.Equal(notification.NotificationData, srcNatDData) {
				ikeLog.Tracef("N3IWF is behind NAT")
				n3iwfBehindNAT = true
			}
		case ike_message.NAT_DETECTION_DESTINATION_IP:
			ikeLog.Tracef("Received IKE Notify: NAT_DETECTION_DESTINATION_IP")
			if !bytes.Equal(notification.NotificationData, dstNatDData) {
				ikeLog.Tracef("UE(SPI: %016x) is behind NAT", responderSPI)
				ueBehindNAT = true
			}
		default:
		}
	}
	return ueBehindNAT, n3iwfBehindNAT, nil
}

func BuildNATDetectNotifPayload(
	localSPI uint64, remoteSPI uint64,
	payload *ike_message.IKEPayloadContainer,
	ueAddr, n3iwfAddr *net.UDPAddr,
) error {
	srcNatDHash, err := GenerateNATDetectHash(localSPI, remoteSPI, ueAddr)
	if err != nil {
		return errors.Wrapf(err, "build NATD")
	}
	// Build and append notify payload for NAT_DETECTION_SOURCE_IP
	payload.BuildNotification(
		ike_message.TypeNone, ike_message.NAT_DETECTION_SOURCE_IP, nil, srcNatDHash)

	dstNatDHash, err := GenerateNATDetectHash(localSPI, remoteSPI, n3iwfAddr)
	if err != nil {
		return errors.Wrapf(err, "build NATD")
	}
	// Build and append notify payload for NAT_DETECTION_DESTINATION_IP
	payload.BuildNotification(
		ike_message.TypeNone, ike_message.NAT_DETECTION_DESTINATION_IP, nil, dstNatDHash)

	return nil
}

func GenerateNATDetectHash(
	initiatorSPI, responderSPI uint64,
	addr *net.UDPAddr,
) ([]byte, error) {
	// Calculate NAT_DETECTION hash for NAT-T
	// : sha1(ispi | rspi | ip | port)
	natdData := make([]byte, 22)
	binary.BigEndian.PutUint64(natdData[0:8], initiatorSPI)
	binary.BigEndian.PutUint64(natdData[8:16], responderSPI)
	copy(natdData[16:20], addr.IP.To4())
	binary.BigEndian.PutUint16(natdData[20:22], uint16(addr.Port)) // #nosec G115

	sha1HashFunction := sha1.New() // #nosec G401
	_, err := sha1HashFunction.Write(natdData)
	if err != nil {
		return nil, errors.Wrapf(err, "generate NATD Hash")
	}
	return sha1HashFunction.Sum(nil), nil
}

// Retransmit message types
const (
	RETRANSMIT_PACKET = iota
	NEW_PACKET
	INVALID_PACKET
)

// processRetransmitCtx processes retransmission context with Message ID checking
func (s *Server) processRetransmitCtx(
	ikeSA *context.IKESecurityAssociation,
	ikeMsg *ike_message.IKEMessage,
	packet []byte,
) bool {
	if ikeSA == nil {
		return true
	}
	ikeLog := logger.IKELog

	// Reset inbound message timer if DPD is enabled
	if ikeSA.IsUseDPD {
		s.ResetInboundMessageTimer(ikeSA)

		// Update inbound message timestamp
		ikeSA.UpdateInboundMessageTimestamp()
	}

	// Process retransmit message
	needMoreProcess, err := s.processRetransmitMsg(ikeSA, ikeMsg.IKEHeader, packet)
	if err != nil {
		ikeLog.Errorf("processRetransmitCtx(): %v", err)
		return false
	}
	if !needMoreProcess {
		return false
	}

	// Stop request message's retransmit timer send from n3iwue
	if ikeMsg.IsResponse() && ikeSA.GetReqRetransTimer() != nil {
		ikeSA.StopReqRetransTimer()
	}

	// Store request message's hash send from N3IWF
	if !ikeMsg.IsResponse() {
		ikeSA.StoreRspRetransPrevReqHash(packet)
	}
	return true
}

// processRetransmitMsg determines if the message should be processed further
func (s *Server) processRetransmitMsg(
	ikeSA *context.IKESecurityAssociation,
	ikeHeader *ike_message.IKEHeader, packet []byte,
) (bool, error) {
	if ikeSA == nil {
		return false, errors.New("processRetransmitMsg(): ikeSA is nil")
	}
	ikeLog := logger.IKELog
	ikeLog.Tracef("Process retransmit message")

	if !ikeHeader.IsResponse() {
		// For requests from N3IWF, check retransmit status
		status, err := s.isRetransmit(ikeSA, ikeHeader, packet)
		switch status {
		case RETRANSMIT_PACKET:
			ikeLog.Warnf("Received IKE request message retransmission with message ID: %d", ikeHeader.MessageID)
			// Send cached response
			err = SendIkeRawMsg(ikeSA.GetRspRetransPrevRsp(), ikeSA.GetRspRetransUdpConnInfo())
			if err != nil {
				return false, errors.Wrapf(err, "processRetransmitMsg()")
			}
			return false, nil
		case NEW_PACKET:
			return true, nil
		case INVALID_PACKET:
			return false, err
		default:
			return false, errors.New("processRetransmitMsg(): invalid retransmit status")
		}
	} else {
		if ikeHeader.MessageID == ikeSA.InitiatorMessageID {
			return true, nil
		} else {
			return false, fmt.Errorf("processRetransmitMsg(): Response expected message ID: %d but received message ID: %d",
				ikeSA.InitiatorMessageID, ikeHeader.MessageID)
		}
	}
}

func (s *Server) switchWifiForHandover(ctx *context.HandoverExecutionContext) error {
	if ctx == nil {
		return fmt.Errorf("handover context is nil")
	}
	if ctx.Wifi == nil {
		return fmt.Errorf("wifi config missing in handover context")
	}
	ueIface := s.Context().N3ueInfo.IPSecIfaceName
	manager := &nmcliWifiManager{}
	prev, err := manager.Switch(ctx.Wifi)
	if err != nil {
		return err
	}

	newIP, err := currentIPv4Addr(ueIface)
	if err != nil {
		return fmt.Errorf("detect UE IP on %s: %w", ueIface, err)
	}
	if err := s.rebindIKEConnections(newIP); err != nil {
		return fmt.Errorf("rebind IKE sockets: %w", err)
	}
	n3ueSelf := s.Context()
	n3ueSelf.N3ueInfo.IPSecIfaceAddr = newIP

	s.captureSourceWifi(prev, ueIface)
	return nil
}

func (s *Server) buildHandoverFailurePayload(reason, detail string) *ike_message.IKEPayloadContainer {
	payload := new(ike_message.IKEPayloadContainer)
	msg := reason
	if detail != "" {
		msg = fmt.Sprintf("%s: %s", reason, detail)
	}
	payload.BuildNotification(ike_message.TypeNone, handoverFailureNotifyType, nil, []byte(msg))
	return payload
}

func (s *Server) captureSourceWifi(prevSSID, iface string) {
	n3ueSelf := s.Context()
	if prevSSID != "" {
		n3ueSelf.SourceWifiSSID = prevSSID
	}
	if iface != "" {
		n3ueSelf.SourceWifiIface = iface
	}
}

func currentIPv4Addr(ifaceName string) (string, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", fmt.Errorf("lookup iface %s: %w", ifaceName, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("list addrs on %s: %w", ifaceName, err)
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ip := ipNet.IP.To4(); ip != nil {
				return ip.String(), nil
			}
		}
	}
	return "", fmt.Errorf("no IPv4 address found on %s", ifaceName)
}

func snapshotIKEEndpoints(n3ueSelf *context.N3UE) map[int]*net.UDPAddr {
	out := make(map[int]*net.UDPAddr)
	if n3ueSelf == nil {
		return out
	}
	for port, info := range n3ueSelf.IKEConnection {
		if info != nil && info.N3IWFAddr != nil {
			out[port] = cloneUDPAddr(info.N3IWFAddr)
		}
	}
	return out
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   cloneIP(addr.IP),
		Port: addr.Port,
		Zone: addr.Zone,
	}
}

func (s *Server) startHandoverFallbackTimer(ctx *context.HandoverExecutionContext) {
	n3ueSelf := s.Context()
	if n3ueSelf == nil || ctx == nil {
		return
	}

	timeout := s.Config().Configuration.N3UEInfo.HandoverFallback
	if timeout == 0 {
		timeout = 60 * time.Second
	}

	if n3ueSelf.HandoverFallbackTimer != nil {
		n3ueSelf.HandoverFallbackTimer.Stop()
	}

	n3ueSelf.HandoverFallbackTimer = time.AfterFunc(timeout, func() {
		s.fallbackToSource(ctx)
	})
}

func (s *Server) cancelHandoverFallbackTimer() {
	n3ueSelf := s.Context()
	if n3ueSelf != nil && n3ueSelf.HandoverFallbackTimer != nil {
		n3ueSelf.HandoverFallbackTimer.Stop()
		n3ueSelf.HandoverFallbackTimer = nil
	}
}

func (s *Server) fallbackToSource(ctx *context.HandoverExecutionContext) {
	ikeLog := logger.IKELog
	n3ueSelf := s.Context()
	if n3ueSelf == nil {
		return
	}
	if n3ueSelf.PendingHandover != ctx {
		return
	}

	ikeLog.Warn("Handover fallback timer expired, reverting to source N3IWF and AP")

	s.cancelHandoverFallbackTimer()
	s.reconnectSourceWifi(n3ueSelf)

	if ctx.SourceN3iwfIP != nil {
		n3ueSelf.N3iwfInfo.IPSecIfaceAddr = ctx.SourceN3iwfIP.String()
	}

	for port, addr := range n3ueSelf.SourceIKEEndpoints {
		if conn, ok := n3ueSelf.IKEConnection[port]; ok && conn != nil {
			conn.N3IWFAddr = cloneUDPAddr(addr)
		}
	}

	n3ueSelf.PendingHandover = nil
	n3ueSelf.NeedMobilityRegUpdate = false
	s.SendIkeEvt(context.NewStartIkeSaEstablishmentEvt())
}

func (s *Server) reconnectSourceWifi(n3ueSelf *context.N3UE) {
	if n3ueSelf == nil {
		return
	}
	if n3ueSelf.SourceWifiSSID == "" || n3ueSelf.SourceWifiIface == "" {
		logger.IKELog.Warn("No source Wi-Fi info to reconnect")
		return
	}
	manager := &nmcliWifiManager{}
	if _, err := manager.Switch(&context.WifiHandoverInfo{
		SSID: n3ueSelf.SourceWifiSSID,
	}); err != nil {
		logger.IKELog.Warnf("Failed to reconnect source Wi-Fi %q on %s: %v", n3ueSelf.SourceWifiSSID, n3ueSelf.SourceWifiIface, err)
		return
	}
	logger.IKELog.Infof("Reconnected to source Wi-Fi %q on %s", n3ueSelf.SourceWifiSSID, n3ueSelf.SourceWifiIface)
}

func (s *Server) isRetransmit(
	ikeSA *context.IKESecurityAssociation,
	ikeHeader *ike_message.IKEHeader, packet []byte,
) (int, error) {
	if ikeSA == nil {
		return INVALID_PACKET, errors.New("isRetransmit(): ikeSA is nil")
	}

	if ikeHeader.MessageID == ikeSA.ResponderMessageID+1 {
		return NEW_PACKET, nil
	}

	if ikeHeader.MessageID != ikeSA.ResponderMessageID {
		return INVALID_PACKET,
			fmt.Errorf("isRetransmit(): Expected message ID: %d or %d but received message ID: %d",
				ikeSA.ResponderMessageID, ikeSA.ResponderMessageID+1, ikeHeader.MessageID)
	}

	// Check if we have a cached response (indicating we processed this request before)
	if ikeSA.GetRspRetransPrevRsp() == nil {
		logger.IKELog.Warnf("isRetransmit(): Received potential retransmit but no cached response, processing as new")
		return NEW_PACKET, nil
	}

	// Compare SHA1 hashes to determine if it's truly a retransmit
	hash := sha1.Sum(packet) // #nosec G401
	prevHash := ikeSA.GetRspRetransPrevReqHash()

	// Compare the incoming request message with the previous request message (same msgID)
	if bytes.Equal(hash[:], prevHash[:]) {
		return RETRANSMIT_PACKET, nil
	}
	return INVALID_PACKET, errors.New("isRetransmit(): message is not retransmit")
}

// handleIkeRetransTimeoutEvt handles IKE retransmission timeout events
func (s *Server) handleIkeRetransTimeout() {
	ikeLog := logger.IKELog
	ikeLog.Tracef("Handle IKE retransmission timeout")

	n3ueCtx := s.Context()
	if n3ueCtx.N3IWFUe == nil || n3ueCtx.N3IWFUe.N3IWFIKESecurityAssociation == nil {
		ikeLog.Warn("No IKE SA found for retransmission")
		return
	}

	ikeSA := n3ueCtx.N3IWFUe.N3IWFIKESecurityAssociation

	// Get retransmit information
	timer := ikeSA.GetReqRetransTimer()
	prevReq := ikeSA.GetReqRetransPrevReq()
	udpConnInfo := ikeSA.GetReqRetransUdpConnInfo()

	if timer == nil || prevReq == nil || udpConnInfo == nil {
		ikeLog.Warn("Incomplete retransmit information, cannot retransmit")
		ikeSA.StopReqRetransTimer()
		return
	}

	// Check if we have retries left
	if timer.GetRetryCount() == 0 {
		ikeLog.Warnf("Maximum retransmission attempts reached, triggering reconnection")

		if s.Config().Configuration.N3UEInfo.AutoReRegistration {
			// Trigger IKE reconnection if re-registration is allowed
			s.handleIkeReconnect()
		} else {
			// Trigger graceful shutdown if re-registration is not allowed
			s.TriggerGracefulShutdown("maximum IKE retransmission attempts reached")
		}

		return
	}

	// Increment retry count and retransmit the packet
	timer.DecrementRetryCount()
	ikeLog.Tracef("Retransmitting IKE packet (retry %d/%d)",
		timer.GetRetryCount(), timer.MaxRetryTimes)

	// Send the retransmitted packet
	err := SendIkeRawMsg(prevReq, udpConnInfo)
	if err != nil {
		ikeLog.Errorf("Failed to retransmit IKE packet: %v", err)
		ikeSA.StopReqRetransTimer()
		return
	}

	delayTime := timer.GetNextDelay()
	timer.Timer = time.AfterFunc(delayTime, func() {
		s.SendIkeEvt(context.NewIkeRetransTimeoutEvt())
	})
}

// shouldProcessRetransmit checks if message should be processed for retransmit
func (s *Server) shouldProcessRetransmit(ikeMsg *ike_message.IKEMessage, packet []byte) bool {
	n3ueCtx := s.Context()
	if n3ueCtx.N3IWFUe == nil || n3ueCtx.N3IWFUe.N3IWFIKESecurityAssociation == nil {
		return false // No IKE SA, continue normal processing
	}

	ikeSA := n3ueCtx.N3IWFUe.N3IWFIKESecurityAssociation
	return s.processRetransmitCtx(ikeSA, ikeMsg, packet)
}

// StartInboundMessageTimer starts the inbound message timer for DPD
func (s *Server) StartInboundMessageTimer(ikeSA *context.IKESecurityAssociation) {
	ikeLog := logger.IKELog
	if ikeSA == nil {
		return
	}

	dpdInterval := factory.N3ueConfig.Configuration.N3UEInfo.DpdInterval
	if dpdInterval == 0 {
		return
	}

	ikeLog.Tracef("Starting inbound message timer for DPD with interval: %v", dpdInterval)

	ikeSA.InboundMessageTimer = time.AfterFunc(dpdInterval, func() {
		ikeLog.Tracef("Inbound message timer timeout, triggering DPD check")
		s.SendIkeEvt(context.NewDpdCheckEvt())
	})
}

// ResetInboundMessageTimer resets the inbound message timer
func (s *Server) ResetInboundMessageTimer(ikeSA *context.IKESecurityAssociation) {
	if ikeSA == nil {
		return
	}

	// Stop existing timer
	ikeSA.StopInboundMessageTimer()
	// Start new timer
	s.StartInboundMessageTimer(ikeSA)
}

// handleDpdCheck handles DPD check events
func (s *Server) handleDpdCheck() {
	ikeLog := logger.IKELog
	n3ue := s.Context()

	if n3ue.N3IWFUe == nil || n3ue.N3IWFUe.N3IWFIKESecurityAssociation == nil {
		ikeLog.Warn("No IKE SA found for DPD check")
		return
	}

	ikeSA := n3ue.N3IWFUe.N3IWFIKESecurityAssociation
	ikeLog.Tracef("Handle DPD check event")

	dpdInterval := factory.N3ueConfig.Configuration.N3UEInfo.DpdInterval
	if dpdInterval == 0 {
		ikeLog.Tracef("DPD is disabled, skip DPD check")
		return
	}

	var sendDpd bool

	// Check if we need to send DPD based on inbound message timestamp
	if ikeSA.GetReqRetransTimer() == nil { // No ongoing retransmissions
		now := time.Now()
		lastInboundTime := time.Unix(ikeSA.InboundMessageTimestamp, 0)

		ikeLog.Tracef("Last inbound message time: %v, now: %v", lastInboundTime, now)

		// If no inbound message for DPD interval, send DPD
		if now.Sub(lastInboundTime) > dpdInterval {
			ikeLog.Tracef("Sending DPD message")
			ikeSA.InitiatorMessageID++
			s.SendN3iwfInformationExchange(n3ue, nil, true, false, ikeSA.InitiatorMessageID)
			sendDpd = true
		}
	}

	// Reset the timer for next check
	s.ResetInboundMessageTimer(ikeSA)

	if !sendDpd {
		ikeLog.Tracef("DPD check completed, no message needed")
	}
}

// handleIkeReconnect handles IKE connection failure events for reconnection
func (s *Server) handleIkeReconnect() {
	ikeLog := logger.IKELog
	ikeLog.Warnf("Handle IKE connection failed - initiating reconnection")

	n3ue := s.Context()
	ikeSA := n3ue.N3IWFUe.N3IWFIKESecurityAssociation

	ikeSA.StopReqRetransTimer()
	ikeSA.StopInboundMessageTimer()

	if err := s.CleanChildSAXfrm(); err != nil {
		ikeLog.Errorf("CleanChildSAXfrm error: %v", err)
	}

	// Cleanup XFRM interfaces
	n3ue.CleanupXfrmIf()

	// Reset all IKE context to prepare for reconnection
	ikeConn := n3ue.IKEConnection
	if err := factory.Initialize(); err != nil {
		ikeLog.Errorf("handleIkeConnectionFailed(): %v", err)
	}

	util.InitN3UEContext()
	n3ue.IKEConnection = ikeConn

	// Trigger procedure restart via RestartRegistration event
	s.SendProcedureEvt(context.NewRestartRegistrationEvt())
}
