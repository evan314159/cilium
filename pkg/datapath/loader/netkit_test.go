// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package loader

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

type egressProgEndpoint struct {
	testutils.TestEndpoint
	requireEgressProg bool
}

func (e *egressProgEndpoint) RequireEgressProg() bool { return e.requireEgressProg }

func TestCheckNetkitBPFCtx(t *testing.T) {
	oldL7 := option.Config.EnableL7Proxy
	t.Cleanup(func() { option.Config.EnableL7Proxy = oldL7 })

	rx := &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{Name: "lxc-rx"}, BPFCtx: netlink.NETKIT_BPF_CTX_RX}
	primary := &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{Name: "lxc-primary"}, BPFCtx: netlink.NETKIT_BPF_CTX_PRIMARY}
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "lxc-veth"}}

	for _, tc := range []struct {
		name      string
		l7        bool
		egress    bool
		iface     netlink.Link
		wantError bool
	}{
		{name: "rx, l7, endpoint routes", l7: true, egress: true, iface: rx, wantError: true},
		{name: "primary, l7, endpoint routes", l7: true, egress: true, iface: primary},
		{name: "rx, no l7", l7: false, egress: true, iface: rx},
		{name: "rx, no endpoint routes", l7: true, egress: false, iface: rx},
		{name: "veth, l7, endpoint routes", l7: true, egress: true, iface: veth},
	} {
		t.Run(tc.name, func(t *testing.T) {
			option.Config.EnableL7Proxy = tc.l7
			ep := &egressProgEndpoint{TestEndpoint: testutils.NewTestEndpoint(t), requireEgressProg: tc.egress}
			err := checkNetkitBPFCtx(ep, tc.iface)
			if tc.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
