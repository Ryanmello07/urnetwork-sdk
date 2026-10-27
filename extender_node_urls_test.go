//go:build !js

package sdk

import (
	"context"
	"testing"

	"github.com/urnetwork/connect"
)

// A storage-less space takes its gossip mode from its embedder (D5): built in
// the feed role it runs no member node, and the mode it is given or later set
// is the one it reports, since it has no `.extender_gossip_mode` to persist.
func TestUrlsSpaceGossipMode(t *testing.T) {
	testEnableExtenderNode(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	newSpace := func(mode string) *NetworkSpace {
		networkSpace := NewNetworkSpaceWithUrlsAndGossipMode(
			ctx,
			"https://api.space.example",
			"wss://connect.space.example",
			connect.DefaultClientStrategySettings(),
			mode,
		)
		t.Cleanup(networkSpace.Close)
		if networkSpace.extenderDirectory == nil {
			t.Fatal("the space has no extender directory, so the test proves nothing")
		}
		return networkSpace
	}

	memberSpace := newSpace(ExtenderGossipModeAuto)
	if memberSpace.getExtenderNode() == nil {
		t.Fatal("the auto mode ran no member node")
	}
	if mode := memberSpace.GetExtenderGossipMode(); mode != ExtenderGossipModeAuto {
		t.Fatalf("mode = %s, expected auto", mode)
	}

	feedSpace := newSpace(ExtenderGossipModeFeed)
	if feedSpace.getExtenderNode() != nil {
		t.Fatal("the feed mode ran a member node")
	}
	if role := feedSpace.GetExtenderStatus().Role; role != ExtenderRoleFeed {
		t.Fatalf("role = %s, expected feed", role)
	}
	// a rebuild, which a settings change or a new extender seed makes, keeps
	// the role the space was built with
	feedSpace.rebuildExtenderNode()
	if feedSpace.getExtenderNode() != nil {
		t.Fatal("a rebuild ran a member node in the feed mode")
	}

	// the mode set later is held in memory
	memberSpace.SetExtenderGossipMode(ExtenderGossipModeFeed)
	if mode := memberSpace.GetExtenderGossipMode(); mode != ExtenderGossipModeFeed {
		t.Fatalf("mode = %s after set, expected feed", mode)
	}

	// NewNetworkSpaceWithUrls keeps auto
	plainSpace := NewNetworkSpaceWithUrls(
		ctx,
		"https://api.space.example",
		"wss://connect.space.example",
		connect.DefaultClientStrategySettings(),
	)
	defer plainSpace.Close()
	if mode := plainSpace.GetExtenderGossipMode(); mode != ExtenderGossipModeAuto {
		t.Fatalf("mode = %s, expected auto", mode)
	}
}
