//go:build !ios_extension

package sdk

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// Fixed values, none computed here: the first two are the pairing uri and the
// wallet link value of walletconnect/wire/vectors_test.go (pairingUri,
// novaLink), the third is the second with its first colon left as it is.
const (
	bittensorTestPairingUri          = "wc:59c972aedb6c86a0b0671be5ab622856e50ac00d51dc80c084e3b2a2f035d434@2?relay-protocol=irn&symKey=587d5484ce2a2a6ee3ba1962fdd7e8588e06200c46823bd18fbd67def96ad303&expiryTimestamp=1700000300&methods=[wc_sessionPropose]"
	bittensorTestPairingUriEnc       = "wc%3A59c972aedb6c86a0b0671be5ab622856e50ac00d51dc80c084e3b2a2f035d434%402%3Frelay-protocol%3Dirn%26symKey%3D587d5484ce2a2a6ee3ba1962fdd7e8588e06200c46823bd18fbd67def96ad303%26expiryTimestamp%3D1700000300%26methods%3D%5Bwc_sessionPropose%5D"
	bittensorTestPairingUriEncKeepWc = "wc:59c972aedb6c86a0b0671be5ab622856e50ac00d51dc80c084e3b2a2f035d434%402%3Frelay-protocol%3Dirn%26symKey%3D587d5484ce2a2a6ee3ba1962fdd7e8588e06200c46823bd18fbd67def96ad303%26expiryTimestamp%3D1700000300%26methods%3D%5Bwc_sessionPropose%5D"
	bittensorTestRequestId           = int64(1759900000000456)
)

// On android Talisman is the one wallet app, in front; on ios it is the first
// of the wallets that sign by copy and paste (delta 3.1).
var bittensorTestPhoneChoiceIds = []string{BittensorWalletTalisman, BittensorWalletTaoCom}

// bittensorTestListWalletApp lists an entry of the wallet-app table on a phone
// platform until the test ends: the table is swapped for a copy with the flag
// set and put back, and is itself never written. Not for a parallel test.
func bittensorTestListWalletApp(t *testing.T, walletId string, platform string) {
	t.Helper()
	tabled := bittensorWalletApps
	apps := slices.Clone(tabled)
	i := slices.IndexFunc(apps, func(entry bittensorWalletAppEntry) bool { return entry.walletId == walletId })
	if i < 0 {
		t.Fatalf("the table has no wallet app %q", walletId)
	}
	if platform == BittensorWalletPlatformIos {
		apps[i].ios.listed = true
	} else {
		apps[i].android.listed = true
	}
	bittensorWalletApps = apps
	t.Cleanup(func() { bittensorWalletApps = tabled })
}

// bittensorTestCheckChoice holds the row of an id that the platform's chooser
// offers against what it has to be: for a wallet app (appName is not "") the
// name, wallet_app and what the entry has for the platform; for any other
// row what bittensor_wallet.go answers and nothing else.
func bittensorTestCheckChoice(t *testing.T, walletId string, platform string, appName string) {
	t.Helper()
	displayName, transport := BittensorWalletDisplayName(walletId), BittensorWalletTransportFor(walletId, platform)
	links := &bittensorWalletAppLinks{}
	if appName != "" {
		displayName, transport = appName, BittensorWalletTransportWalletApp
		if _, links = bittensorWalletAppEntryFor(walletId, platform); links == nil {
			t.Errorf("%s on %s: no entry", walletId, platform)
			return
		}
	}
	choice := BittensorWalletChoiceFor(walletId, platform)
	if choice == nil || choice.Packages == nil || choice.PackageSigners == nil {
		t.Errorf("%s on %s: %+v, want a row with both lists", walletId, platform, choice)
		return
	}
	const format = "id %q, name %q, transport %q, probe %q, universal link only %t, packages %q, signers %q"
	got := fmt.Sprintf(format, choice.WalletId, choice.DisplayName, choice.Transport, choice.ProbeUrl, choice.UniversalLinkOnly, choice.Packages.values, choice.PackageSigners.values)
	want := fmt.Sprintf(format, walletId, displayName, transport, links.probeUrl, links.universalLinkOnly, links.packages, links.signers)
	if got != want {
		t.Errorf("%s on %s: %s; want %s", walletId, platform, got, want)
	}
}

// TC15a: the chooser of every platform.
func TestBittensorWalletChoiceIdList(t *testing.T) {
	desktop := BittensorWalletIdList().values
	for platform, want := range map[string][]string{
		BittensorWalletPlatformIos:     bittensorTestPhoneChoiceIds,
		BittensorWalletPlatformAndroid: bittensorTestPhoneChoiceIds,
		BittensorWalletPlatformMacos:   desktop,
		BittensorWalletPlatformWindows: desktop,
		BittensorWalletPlatformLinux:   desktop,
		BittensorWalletPlatformWeb:     desktop,
		"tvos":                         nil,
	} {
		if got := BittensorWalletChoiceIdList(platform); got == nil || !slices.Equal(got.values, want) {
			t.Errorf("%s: %+v, want %v", platform, got, want)
		}
	}
}

// TC15b: every row of every chooser, and no row for an id a chooser does
// not offer.
func TestBittensorWalletChoiceRows(t *testing.T) {
	rows := 0
	for _, platform := range []string{
		BittensorWalletPlatformIos, BittensorWalletPlatformAndroid, BittensorWalletPlatformMacos,
		BittensorWalletPlatformWindows, BittensorWalletPlatformLinux, BittensorWalletPlatformWeb,
	} {
		for _, walletId := range BittensorWalletChoiceIdList(platform).values {
			// the one wallet app a chooser lists: Talisman, and on android only
			appName := ""
			if walletId == BittensorWalletTalisman && platform == BittensorWalletPlatformAndroid {
				appName = "Talisman"
			}
			bittensorTestCheckChoice(t, walletId, platform, appName)
			rows += 1
		}
	}
	// two phones with two rows, four other platforms with three
	if rows != 16 {
		t.Errorf("%d rows, want 16", rows)
	}
	if BittensorWalletChoiceFor(BittensorWalletWalletConnect, BittensorWalletPlatformIos) != nil ||
		BittensorWalletChoiceFor(BittensorWalletNova, BittensorWalletPlatformMacos) != nil {
		t.Error("a row for an id the platform's chooser does not offer")
	}
}

// TC15c, as the links of the whole table (design C.2): every template of
// every entry, expanded.
func TestBittensorWalletChoiceLinks(t *testing.T) {
	for _, c := range []struct {
		walletId   string
		platform   string
		pair       string
		foreground string
	}{
		{BittensorWalletNova, BittensorWalletPlatformIos, "novawallet://wc?uri=" + bittensorTestPairingUriEnc, "novawallet://request"},
		{BittensorWalletNova, BittensorWalletPlatformAndroid, bittensorTestPairingUri, "novawallet://request"},
		{BittensorWalletSubWallet, BittensorWalletPlatformIos, "subwallet://wc?uri=" + bittensorTestPairingUriEnc, "subwallet://wc?requestId=1759900000000456"},
		{BittensorWalletSubWallet, BittensorWalletPlatformAndroid, "subwallet://wc?uri=" + bittensorTestPairingUriEnc, "subwallet://wc?requestId=1759900000000456"},
		{BittensorWalletTalisman, BittensorWalletPlatformIos, "https://talisman.xyz/wc?uri=" + bittensorTestPairingUriEncKeepWc, ""},
		// no link brings it forward there: the app starts the package (BittensorWalletLinkLaunchPackage)
		{BittensorWalletTalisman, BittensorWalletPlatformAndroid, "https://talisman.xyz/wc?uri=" + bittensorTestPairingUriEncKeepWc, "launch-package:"},
		{BittensorWalletWalletConnect, BittensorWalletPlatformIos, "", ""},
		{BittensorWalletWalletConnect, BittensorWalletPlatformAndroid, "", ""},
	} {
		_, links := bittensorWalletAppEntryFor(c.walletId, c.platform)
		if links == nil {
			t.Errorf("%s on %s: no entry", c.walletId, c.platform)
			continue
		}
		if got := bittensorWalletAppLink(links.pair, bittensorTestPairingUri, bittensorTestRequestId); got != c.pair {
			t.Errorf("%s on %s, pair: %q, want %q", c.walletId, c.platform, got, c.pair)
		}
		if got := bittensorWalletAppLink(links.foreground, bittensorTestPairingUri, bittensorTestRequestId); got != c.foreground {
			t.Errorf("%s on %s, foreground: %q, want %q", c.walletId, c.platform, got, c.foreground)
		}
	}
}

// TC15d: the signing certificates of the android packages.
func TestBittensorWalletChoiceSigners(t *testing.T) {
	signers := 0
	for _, entry := range bittensorWalletApps {
		for _, links := range []bittensorWalletAppLinks{entry.ios, entry.android} {
			for _, signer := range links.signers {
				signers += 1
				pkg, digest, _ := strings.Cut(signer, " ")
				if !slices.Contains(links.packages, pkg) || len(digest) != 64 || strings.Trim(digest, "0123456789abcdef") != "" {
					t.Errorf("%s: the signer %q is not a package of %v and 64 lowercase hex", entry.walletId, signer, links.packages)
				}
			}
			for _, pkg := range links.packages {
				if !slices.ContainsFunc(links.signers, func(signer string) bool { return strings.HasPrefix(signer, pkg+" ") }) {
					t.Errorf("%s: the package %s has no signer", entry.walletId, pkg)
				}
			}
		}
	}
	// two of Nova, one of SubWallet, two of Talisman
	if signers != 5 {
		t.Errorf("%d signers, want 5", signers)
	}
	// no source publishes the certificate of Nova's GitHub build (design C.2)
	if strings.Contains(fmt.Sprint(bittensorWalletApps), "io.novafoundation.nova.github") {
		t.Error("the table names io.novafoundation.nova.github")
	}
}

// TC15e: an entry that is not listed on a platform is in the table all the
// same, and listing it there is that flag and nothing else.
func TestBittensorWalletChoiceUnlistedEntries(t *testing.T) {
	for _, c := range []struct {
		walletId string
		platform string
		tabled   bool
	}{
		{BittensorWalletNova, BittensorWalletPlatformIos, true},
		{BittensorWalletSubWallet, BittensorWalletPlatformAndroid, true},
		{BittensorWalletTalisman, BittensorWalletPlatformIos, true},
		{BittensorWalletWalletConnect, BittensorWalletPlatformAndroid, true},
		{BittensorWalletTalisman, BittensorWalletPlatformMacos, false},
		{BittensorWalletTaoCom, BittensorWalletPlatformIos, false},
	} {
		entry, links := bittensorWalletAppEntryFor(c.walletId, c.platform)
		if (entry != nil) != c.tabled || (links != nil) != c.tabled || links != nil && links.listed {
			t.Fatalf("%s on %s: %+v, %+v", c.walletId, c.platform, entry, links)
		}
	}

	// Nova on android comes in front, in table order. Talisman on ios stays
	// where it is and becomes a wallet app whose link is an https one: there
	// it must never reach a browser.
	bittensorTestListWalletApp(t, BittensorWalletNova, BittensorWalletPlatformAndroid)
	bittensorTestListWalletApp(t, BittensorWalletTalisman, BittensorWalletPlatformIos)
	for platform, want := range map[string][]string{
		BittensorWalletPlatformAndroid: {BittensorWalletNova, BittensorWalletTalisman, BittensorWalletTaoCom},
		BittensorWalletPlatformIos:     bittensorTestPhoneChoiceIds,
	} {
		if got := BittensorWalletChoiceIdList(platform); !slices.Equal(got.values, want) {
			t.Errorf("%s with one more entry listed: %v, want %v", platform, got.values, want)
		}
		bittensorTestCheckChoice(t, BittensorWalletTalisman, platform, "Talisman")
		if choice := BittensorWalletChoiceFor(BittensorWalletTalisman, platform); choice != nil && choice.UniversalLinkOnly != (platform == BittensorWalletPlatformIos) {
			t.Errorf("talisman on %s: UniversalLinkOnly %t", platform, choice.UniversalLinkOnly)
		}
		if got := BittensorWalletTransportFor(BittensorWalletTalisman, platform); got != BittensorWalletTransportManual {
			t.Errorf("BittensorWalletTransportFor(talisman, %s) with talisman listed: %q", platform, got)
		}
	}
	bittensorTestCheckChoice(t, BittensorWalletNova, BittensorWalletPlatformAndroid, "Nova Wallet")
}
