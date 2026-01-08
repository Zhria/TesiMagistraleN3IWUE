package xfrm

import (
	"fmt"
	"net"
	"strings"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"

	ike_message "github.com/free5gc/ike/message"
	context "github.com/free5gc/n3iwue/pkg/context"
)

type XFRMEncryptionAlgorithmType uint16

func (xfrmEncryptionAlgorithmType XFRMEncryptionAlgorithmType) String() string {
	switch xfrmEncryptionAlgorithmType {
	case ike_message.ENCR_DES:
		return "cbc(des)"
	case ike_message.ENCR_3DES:
		return "cbc(des3_ede)"
	case ike_message.ENCR_CAST:
		return "cbc(cast5)"
	case ike_message.ENCR_BLOWFISH:
		return "cbc(blowfish)"
	case ike_message.ENCR_NULL:
		return "ecb(cipher_null)"
	case ike_message.ENCR_AES_CBC:
		return "cbc(aes)"
	case ike_message.ENCR_AES_CTR:
		return "rfc3686(ctr(aes))"
	default:
		return ""
	}
}

type XFRMIntegrityAlgorithmType uint16

func (xfrmIntegrityAlgorithmType XFRMIntegrityAlgorithmType) String() string {
	switch xfrmIntegrityAlgorithmType {
	case ike_message.AUTH_HMAC_MD5_96:
		return "hmac(md5)"
	case ike_message.AUTH_HMAC_SHA1_96:
		return "hmac(sha1)"
	case ike_message.AUTH_AES_XCBC_96:
		return "xcbc(aes)"
	default:
		return ""
	}
}

func ApplyXFRMRule(
	ue_is_initiator bool,
	ifId uint32,
	childSecurityAssociation *context.ChildSecurityAssociation,
) error {
	// Build XFRM information data structure for incoming traffic.

	// Mark
	// mark := &netlink.XfrmMark{
	// 	Value: ifMark, // n3ueInfo.XfrmMark,
	// }

	// Direction: N3IWF -> UE
	// State
	var xfrmEncryptionAlgorithm, xfrmIntegrityAlgorithm *netlink.XfrmStateAlgo
	if ue_is_initiator {
		xfrmEncryptionAlgorithm = &netlink.XfrmStateAlgo{
			Name: XFRMEncryptionAlgorithmType(childSecurityAssociation.EncrKInfo.TransformID()).String(),
			Key:  childSecurityAssociation.ResponderToInitiatorEncryptionKey,
		}
		if childSecurityAssociation.IntegKInfo != nil {
			xfrmIntegrityAlgorithm = &netlink.XfrmStateAlgo{
				Name: XFRMIntegrityAlgorithmType(childSecurityAssociation.IntegKInfo.TransformID()).String(),
				Key:  childSecurityAssociation.ResponderToInitiatorIntegrityKey,
			}
		}
	} else {
		xfrmEncryptionAlgorithm = &netlink.XfrmStateAlgo{
			Name: XFRMEncryptionAlgorithmType(childSecurityAssociation.EncrKInfo.TransformID()).String(),
			Key:  childSecurityAssociation.InitiatorToResponderEncryptionKey,
		}
		if childSecurityAssociation.IntegKInfo != nil {
			xfrmIntegrityAlgorithm = &netlink.XfrmStateAlgo{
				Name: XFRMIntegrityAlgorithmType(childSecurityAssociation.IntegKInfo.TransformID()).String(),
				Key:  childSecurityAssociation.InitiatorToResponderIntegrityKey,
			}
		}
	}

	xfrmState := new(netlink.XfrmState)

	xfrmState.Src = childSecurityAssociation.PeerPublicIPAddr
	xfrmState.Dst = childSecurityAssociation.LocalPublicIPAddr
	xfrmState.Proto = netlink.XFRM_PROTO_ESP
	xfrmState.Mode = netlink.XFRM_MODE_TUNNEL
	xfrmState.Spi = int(childSecurityAssociation.InboundSPI)
	xfrmState.Ifid = int(ifId)
	xfrmState.Auth = xfrmIntegrityAlgorithm
	xfrmState.Crypt = xfrmEncryptionAlgorithm
	xfrmState.ESN = childSecurityAssociation.EsnInfo.GetNeedESN()

	// Commit xfrm state to netlink
	var err error
	if err = netlink.XfrmStateAdd(xfrmState); err != nil {
		if strings.Contains(err.Error(), "file exists") {
			_ = netlink.XfrmStateDel(xfrmState)
			if err = netlink.XfrmStateAdd(xfrmState); err != nil {
				if cleanupErr := deleteExistingXfrmState(xfrmState); cleanupErr == nil {
					err = netlink.XfrmStateAdd(xfrmState)
				} else {
					return fmt.Errorf("Set XFRM state rule failed: %v (cleanup: %v)", err, cleanupErr)
				}
			}
			if err != nil {
				return fmt.Errorf("Set XFRM state rule failed: %+v", err)
			}
		} else {
			return fmt.Errorf("Set XFRM state rule failed: %+v", err)
		}
	}

	childSecurityAssociation.XfrmStateList = append(childSecurityAssociation.XfrmStateList, *xfrmState)

	// Policy
	xfrmPolicyTemplate := netlink.XfrmPolicyTmpl{
		Src:   xfrmState.Src,
		Dst:   xfrmState.Dst,
		Proto: xfrmState.Proto,
		Mode:  xfrmState.Mode,
		Spi:   xfrmState.Spi,
	}

	xfrmPolicy := new(netlink.XfrmPolicy)

	if childSecurityAssociation.SelectedIPProtocol == 0 {
		return errors.New("Protocol == 0")
	}

	xfrmPolicy.Src = &childSecurityAssociation.TrafficSelectorRemote
	xfrmPolicy.Dst = &childSecurityAssociation.TrafficSelectorLocal
	xfrmPolicy.Proto = netlink.Proto(childSecurityAssociation.SelectedIPProtocol)
	xfrmPolicy.Dir = netlink.XFRM_DIR_IN
	xfrmPolicy.Ifid = int(ifId)
	xfrmPolicy.Tmpls = []netlink.XfrmPolicyTmpl{
		xfrmPolicyTemplate,
	}

	// Commit xfrm policy to netlink
	if err = netlink.XfrmPolicyAdd(xfrmPolicy); err != nil {
		if strings.Contains(err.Error(), "file exists") {
			_ = netlink.XfrmPolicyDel(xfrmPolicy)
			if err = netlink.XfrmPolicyAdd(xfrmPolicy); err != nil {
				if cleanupErr := deleteExistingXfrmPolicy(xfrmPolicy); cleanupErr == nil {
					err = netlink.XfrmPolicyAdd(xfrmPolicy)
				} else {
					return fmt.Errorf("Set XFRM policy rule failed: %v (cleanup: %v)", err, cleanupErr)
				}
			}
			if err != nil {
				return fmt.Errorf("Set XFRM policy rule failed: %+v", err)
			}
		} else {
			return fmt.Errorf("Set XFRM policy rule failed: %+v", err)
		}
	}

	childSecurityAssociation.XfrmPolicyList = append(childSecurityAssociation.XfrmPolicyList, *xfrmPolicy)

	// Direction: UE -> N3IWF
	// State
	if ue_is_initiator {
		xfrmEncryptionAlgorithm.Key = childSecurityAssociation.InitiatorToResponderEncryptionKey
		if childSecurityAssociation.IntegKInfo != nil {
			xfrmIntegrityAlgorithm.Key = childSecurityAssociation.InitiatorToResponderIntegrityKey
		}
	} else {
		xfrmEncryptionAlgorithm.Key = childSecurityAssociation.ResponderToInitiatorEncryptionKey
		if childSecurityAssociation.IntegKInfo != nil {
			xfrmIntegrityAlgorithm.Key = childSecurityAssociation.ResponderToInitiatorIntegrityKey
		}
	}

	xfrmState.Src, xfrmState.Dst = xfrmState.Dst, xfrmState.Src
	xfrmState.Spi = int(childSecurityAssociation.OutboundSPI)

	if childSecurityAssociation.EnableEncapsulate {
		xfrmState.Encap = &netlink.XfrmStateEncap{
			Type:    netlink.XFRM_ENCAP_ESPINUDP,
			SrcPort: childSecurityAssociation.NATPort,
			DstPort: childSecurityAssociation.N3IWFPort,
		}
	}

	// Commit xfrm state to netlink
	if err = netlink.XfrmStateAdd(xfrmState); err != nil {
		if strings.Contains(err.Error(), "file exists") {
			_ = netlink.XfrmStateDel(xfrmState)
			if err = netlink.XfrmStateAdd(xfrmState); err != nil {
				if cleanupErr := deleteExistingXfrmState(xfrmState); cleanupErr == nil {
					err = netlink.XfrmStateAdd(xfrmState)
				} else {
					return fmt.Errorf("Set XFRM state rule failed: %v (cleanup: %v)", err, cleanupErr)
				}
			}
			if err != nil {
				return fmt.Errorf("Set XFRM state rule failed: %+v", err)
			}
		} else {
			return fmt.Errorf("Set XFRM state rule failed: %+v", err)
		}
	}

	childSecurityAssociation.XfrmStateList = append(childSecurityAssociation.XfrmStateList, *xfrmState)

	// Policy
	xfrmPolicyTemplate.Src, xfrmPolicyTemplate.Dst = xfrmPolicyTemplate.Dst, xfrmPolicyTemplate.Src
	xfrmPolicyTemplate.Spi = int(childSecurityAssociation.OutboundSPI)

	xfrmPolicy.Src, xfrmPolicy.Dst = xfrmPolicy.Dst, xfrmPolicy.Src
	xfrmPolicy.Dir = netlink.XFRM_DIR_OUT
	xfrmPolicy.Tmpls = []netlink.XfrmPolicyTmpl{
		xfrmPolicyTemplate,
	}

	// Commit xfrm policy to netlink
	if err = netlink.XfrmPolicyAdd(xfrmPolicy); err != nil {
		if strings.Contains(err.Error(), "file exists") {
			_ = netlink.XfrmPolicyDel(xfrmPolicy)
			if err = netlink.XfrmPolicyAdd(xfrmPolicy); err != nil {
				if cleanupErr := deleteExistingXfrmPolicy(xfrmPolicy); cleanupErr == nil {
					err = netlink.XfrmPolicyAdd(xfrmPolicy)
				} else {
					return fmt.Errorf("Set XFRM policy rule failed: %v (cleanup: %v)", err, cleanupErr)
				}
			}
			if err != nil {
				return fmt.Errorf("Set XFRM policy rule failed: %+v", err)
			}
		} else {
			return fmt.Errorf("Set XFRM policy rule failed: %+v", err)
		}
	}

	childSecurityAssociation.XfrmPolicyList = append(childSecurityAssociation.XfrmPolicyList, *xfrmPolicy)

	return nil
}

func deleteExistingXfrmState(target *netlink.XfrmState) error {
	if target == nil {
		return nil
	}

	states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		return err
	}

	var firstErr error
	for idx := range states {
		state := states[idx]
		if state.Proto != target.Proto {
			continue
		}
		if state.Spi != target.Spi {
			continue
		}
		if state.Ifid != target.Ifid {
			continue
		}
		if !ipEqual(state.Src, target.Src) || !ipEqual(state.Dst, target.Dst) {
			continue
		}

		stateCopy := state
		if err := netlink.XfrmStateDel(&stateCopy); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

func deleteExistingXfrmPolicy(target *netlink.XfrmPolicy) error {
	if target == nil {
		return nil
	}

	policies, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil {
		return err
	}

	var firstErr error
	for idx := range policies {
		policy := policies[idx]
		if policy.Dir != target.Dir {
			continue
		}
		if policy.Ifid != target.Ifid {
			continue
		}
		if policy.Proto != target.Proto {
			continue
		}
		if !ipNetEqual(policy.Src, target.Src) || !ipNetEqual(policy.Dst, target.Dst) {
			continue
		}

		policyCopy := policy
		if err := netlink.XfrmPolicyDel(&policyCopy); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

func ipEqual(a, b net.IP) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(b)
}

func ipNetEqual(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.String() == b.String()
}

func SetupIPsecXfrmi(
	xfrmIfaceName, parentIfaceName string,
	xfrmIfaceId uint32,
	xfrmIfaceAddr *net.IPNet,
) (netlink.Link, error) {
	var (
		xfrmi, parent netlink.Link
		err           error
	)

	if parent, err = netlink.LinkByName(parentIfaceName); err != nil {
		return nil, err
	}

	if xfrmi, err = netlink.LinkByName(xfrmIfaceName); err != nil {
		link := &netlink.Xfrmi{
			LinkAttrs: netlink.LinkAttrs{
				MTU:         1478, //Edit: MTU Reduced due to a PMTU Blackhole. 1478,
				Name:        xfrmIfaceName,
				ParentIndex: parent.Attrs().Index,
			},
			Ifid: xfrmIfaceId,
		}

		// ip link add
		if err = netlink.LinkAdd(link); err != nil {
			// If it already exists, treat it as idempotent and reuse it.
			if xfrmi, err = netlink.LinkByName(xfrmIfaceName); err != nil {
				return nil, err
			}
		} else if xfrmi, err = netlink.LinkByName(xfrmIfaceName); err != nil {
			return nil, err
		}
	}

	if existingXfrmi, ok := xfrmi.(*netlink.Xfrmi); ok {
		if existingXfrmi.Ifid != xfrmIfaceId {
			return nil, fmt.Errorf("xfrmi %s already exists with ifid %d (expected %d)", xfrmIfaceName, existingXfrmi.Ifid, xfrmIfaceId)
		}
		if existingXfrmi.Attrs() != nil && existingXfrmi.Attrs().ParentIndex != parent.Attrs().Index {
			return nil, fmt.Errorf("xfrmi %s already exists with parent index %d (expected %d)", xfrmIfaceName, existingXfrmi.Attrs().ParentIndex, parent.Attrs().Index)
		}
	}

	// ip addr add
	linkIPSecAddr := &netlink.Addr{
		IPNet: xfrmIfaceAddr,
	}

	addrExists := false
	if addrs, addrErr := netlink.AddrList(xfrmi, netlink.FAMILY_ALL); addrErr == nil {
		for _, addr := range addrs {
			if addr.IPNet != nil && xfrmIfaceAddr != nil && addr.IPNet.String() == xfrmIfaceAddr.String() {
				addrExists = true
				break
			}
		}
	}

	if !addrExists {
		if err := netlink.AddrAdd(xfrmi, linkIPSecAddr); err != nil && !strings.Contains(err.Error(), "file exists") {
			return nil, err
		}
	}

	// ip link set ... up
	if err := netlink.LinkSetUp(xfrmi); err != nil {
		return nil, err
	}

	n3ueSelf := context.N3UESelf()
	alreadyTracked := false
	for _, iface := range n3ueSelf.CreatedIface {
		if iface == nil || (*iface).Attrs() == nil {
			continue
		}
		if (*iface).Attrs().Name == xfrmIfaceName {
			alreadyTracked = true
			break
		}
	}
	if !alreadyTracked {
		n3ueSelf.CreatedIface = append(n3ueSelf.CreatedIface, &xfrmi)
	}

	return xfrmi, nil
}

func DeleteChildSAXfrm(childSA *context.ChildSecurityAssociation) error {
	for idx := range childSA.XfrmStateList {
		xfrmState := childSA.XfrmStateList[idx]
		if err := netlink.XfrmStateDel(&xfrmState); err != nil {
			return errors.Wrapf(err, "DeleteChildSaXfrm(): delete xfrm state")
		}
	}

	for idx := range childSA.XfrmPolicyList {
		xfrmPolicy := childSA.XfrmPolicyList[idx]
		if err := netlink.XfrmPolicyDel(&xfrmPolicy); err != nil {
			return errors.Wrapf(err, "DeleteChildSaXfrm(): delete xfrm policy")
		}
	}

	childSA.XfrmStateList = nil
	childSA.XfrmPolicyList = nil
	return nil
}
