// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package loader

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func mustNetkit(t *testing.T) netlink.Link {
	t.Helper()

	if err := probes.HaveNetkit(); err != nil {
		t.Skipf("netkit not supported: %s", err)
	}

	nk := &netlink.Netkit{
		LinkAttrs:  netlink.LinkAttrs{Name: "nk-primary"},
		Mode:       netlink.NETKIT_MODE_L3,
		Policy:     netlink.NETKIT_POLICY_FORWARD,
		PeerPolicy: netlink.NETKIT_POLICY_BLACKHOLE,
	}
	nk.SetPeerAttrs(&netlink.LinkAttrs{Name: "nk-peer"})
	require.NoError(t, netlink.LinkAdd(nk))

	l, err := netlink.LinkByName("nk-primary")
	require.NoError(t, err)
	return l
}

func pinnedLinkType(t *testing.T, pin string) link.Type {
	t.Helper()

	l, err := link.LoadPinnedLink(pin, &ebpf.LoadPinOptions{})
	require.NoError(t, err)
	defer l.Close()

	info, err := l.Info()
	require.NoError(t, err)
	return info.Type
}

func TestPrivilegedAttachNetkitEgressTCX(t *testing.T) {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)

	skipTCXUnsupported(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		nk := mustNetkit(t)
		prog := mustTCProgramWithName(t, "cil_test")
		linkDir := testutils.TempBPFFS(t)
		pin := filepath.Join(linkDir, "cil_test")
		egress := directionToParent(dirEgress)

		// Egress uses tcx on the primary device, not the netkit primary hook.
		require.NoError(t, attachSKBProgram(logger, nk, prog, "cil_test", linkDir, egress, true))
		require.Equal(t, link.TCXType, pinnedLinkType(t, pin))

		hasPrograms, err := hasCiliumTCXLinks(nk, ebpf.AttachTCXEgress)
		require.NoError(t, err)
		require.True(t, hasPrograms)
		hasPrograms, err = hasCiliumNetkitLinks(nk, ebpf.AttachNetkitPrimary)
		require.NoError(t, err)
		require.False(t, hasPrograms)

		// Attaching again updates the tcx link.
		require.NoError(t, attachSKBProgram(logger, nk, prog, "cil_test", linkDir, egress, true))
		require.Equal(t, link.TCXType, pinnedLinkType(t, pin))

		require.NoError(t, detachSKBProgram(logger, nk, "cil_test", linkDir, egress))
		require.NoError(t, testutils.WaitUntil(func() bool {
			hasPrograms, err := hasCiliumTCXLinks(nk, ebpf.AttachTCXEgress)
			require.NoError(t, err)
			return !hasPrograms
		}, time.Second))

		return nil
	})
}

func TestPrivilegedReplaceNetkitPrimaryLink(t *testing.T) {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)

	skipTCXUnsupported(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		nk := mustNetkit(t)
		prog := mustTCProgramWithName(t, "cil_test")
		linkDir := testutils.TempBPFFS(t)
		pin := filepath.Join(linkDir, "cil_test")

		// Link attached to the netkit primary hook by an earlier version.
		require.NoError(t, attachNetkit(logger, nk, prog, "cil_test", linkDir, ebpf.AttachNetkitPrimary))
		require.Equal(t, link.NetkitType, pinnedLinkType(t, pin))

		require.NoError(t, attachSKBProgram(logger, nk, prog, "cil_test", linkDir, directionToParent(dirEgress), true))
		require.Equal(t, link.TCXType, pinnedLinkType(t, pin))

		hasPrograms, err := hasCiliumTCXLinks(nk, ebpf.AttachTCXEgress)
		require.NoError(t, err)
		require.True(t, hasPrograms)
		require.NoError(t, testutils.WaitUntil(func() bool {
			hasPrograms, err := hasCiliumNetkitLinks(nk, ebpf.AttachNetkitPrimary)
			require.NoError(t, err)
			return !hasPrograms
		}, time.Second))

		return nil
	})
}

func TestPrivilegedAttachNetkitIngress(t *testing.T) {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)

	skipTCXUnsupported(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		nk := mustNetkit(t)
		prog := mustTCProgramWithName(t, "cil_test")
		linkDir := testutils.TempBPFFS(t)

		// Ingress keeps using the netkit peer hook.
		require.NoError(t, attachSKBProgram(logger, nk, prog, "cil_test", linkDir, directionToParent(dirIngress), true))
		require.Equal(t, link.NetkitType, pinnedLinkType(t, filepath.Join(linkDir, "cil_test")))

		hasPrograms, err := hasCiliumNetkitLinks(nk, ebpf.AttachNetkitPeer)
		require.NoError(t, err)
		require.True(t, hasPrograms)

		return nil
	})
}
