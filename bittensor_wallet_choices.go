//go:build !ios_extension

package sdk

// The wallet chooser of every platform, and the table of the wallet apps a
// phone opens through a BittensorWalletConnect: names, link templates, android
// packages and their signing certificates. The apps keep no copy of any of
// it. Data and pure functions, safe for concurrent use.

import (
	"net/url"
	"strconv"
	"strings"
)

// Wallet ids of wallet apps a phone can open, beside the ids of bittensor_wallet.go.
const (
	BittensorWalletNova      = "nova"
	BittensorWalletSubWallet = "subwallet"
)

// The transport of a chooser row that opens a wallet app through a
// BittensorWalletConnect. BittensorWalletTransportFor never returns it.
const BittensorWalletTransportWalletApp = "wallet_app"

// What WalletLink and TakeWalletLink answer where a wallet is brought forward
// by starting its app and no link exists for that (android): the app starts
// the launch intent of the package it verified for the row. It is no link and
// carries nothing, the package least of all (delta 3.3).
const BittensorWalletLinkLaunchPackage = "launch-package:"

// BittensorWalletChoice is one row of the wallet chooser on one platform.
type BittensorWalletChoice struct {
	WalletId string
	// the product name; not translated
	DisplayName string
	// BittensorWalletTransportWalletApp: open the wallet app with a
	// BittensorWalletConnect. Any other value is
	// BittensorWalletTransportFor(WalletId, platform): use a
	// BittensorWalletSession exactly as before.
	Transport string
	// wallet_app, ios: a url for canOpenURL that tells whether the wallet is
	// installed ("" = cannot be asked; treat as installed)
	ProbeUrl string
	// wallet_app, ios: open wallet links with universalLinksOnly, so an
	// https link can never reach a browser
	UniversalLinkOnly bool
	// wallet_app, android: the packages a wallet link may be delivered to,
	// in order, always with Intent.setPackage
	Packages *StringList
	// wallet_app, android: "<package> <sha-256 of a signing certificate, 64
	// lowercase hex>". A package is used only when one of its installed
	// signing certificates is listed here.
	PackageSigners *StringList
}

// bittensorWalletAppLinks is what one platform needs to open a wallet app.
// The templates are expanded by bittensorWalletAppLink.
type bittensorWalletAppLinks struct {
	listed            bool     // a row of the platform's chooser
	pair              string   // template that hands the pairing over; "" = none
	foreground        string   // template that brings the wallet forward, or BittensorWalletLinkLaunchPackage; "" = none
	probeUrl          string   // ios
	universalLinkOnly bool     // ios
	packages          []string // android, in order
	signers           []string // android: "<package> <64 lowercase hex>"

	// two more forms of pair, which a device test may ask for
	// (BittensorWalletConnect.SetDeviceTestOptions); "" = none
	pairScheme, pairBare string
}

type bittensorWalletAppEntry struct {
	walletId    string
	displayName string
	ios         bittensorWalletAppLinks
	android     bittensorWalletAppLinks
}

// bittensorWalletApps is the wallet-app table (design C.2 has the source of
// every value, delta 3 what changed after the first phone test). Read only:
// nothing writes it after package init. An entry that is not listed on a
// platform can be connected to there and is no chooser row; listing it is
// that one field (design C.3 rule 7). Listed is what a phone has opened:
// Talisman on android. Nova and SubWallet wait for a run of theirs.
var bittensorWalletApps = []bittensorWalletAppEntry{
	{
		walletId:    BittensorWalletNova,
		displayName: "Nova Wallet",
		ios: bittensorWalletAppLinks{
			pair:       "novawallet://wc?uri={uri_enc}",
			foreground: "novawallet://request",
			probeUrl:   "novawallet://",
		},
		android: bittensorWalletAppLinks{
			// the bare uri, delivered to the package: the form Nova's own
			// source is known to take
			pair:       "{uri}",
			foreground: "novawallet://request",
			packages:   []string{"io.novafoundation.nova.market"},
			signers: []string{
				"io.novafoundation.nova.market cdf40e03e6145a92ed8a666e8ce421f754b316da4dd70eb93db75ea5ea3fb104",
				"io.novafoundation.nova.market 6d32df029ec0107d4a7a063f8d22485d6afc9a4b3377d95f33b7cad35eb9d99d",
			},
		},
	},
	{
		walletId:    BittensorWalletSubWallet,
		displayName: "SubWallet",
		ios: bittensorWalletAppLinks{
			pair:       "subwallet://wc?uri={uri_enc}",
			foreground: "subwallet://wc?requestId={request_id}",
			probeUrl:   "subwallet://",
		},
		android: bittensorWalletAppLinks{
			pair:       "subwallet://wc?uri={uri_enc}",
			foreground: "subwallet://wc?requestId={request_id}",
			packages:   []string{"app.subwallet.mobile"},
			signers: []string{
				"app.subwallet.mobile 823d8dc9b0cfd0ff16da8106153ec13a4ad26a4597fb9d5f0666f959a220012a",
			},
		},
	},
	{
		walletId:    BittensorWalletTalisman,
		displayName: "Talisman",
		ios: bittensorWalletAppLinks{
			listed: false, // nothing was run on an iPhone
			// the app's association file matches "wc:*" on the encoded
			// value, so the first colon stays as it is
			pair:              "https://talisman.xyz/wc?uri={uri_enc_keep_wc}",
			universalLinkOnly: true,
		},
		android: bittensorWalletAppLinks{
			listed: true,
			pair:   "https://talisman.xyz/wc?uri={uri_enc_keep_wc}",
			// it has no link that brings it forward: the app starts it
			foreground: BittensorWalletLinkLaunchPackage,
			packages:   []string{"xyz.talisman.app"},
			signers: []string{
				"xyz.talisman.app 249542ce5087d97454c06910ab727e6d3430575920db0c8a32746a1f2812c86f",
				"xyz.talisman.app 51392890773ad6d76ca52e073a9076c466b16cd0e8cdae03280a1cd89185af39",
			},
			// both opened the app on the phone of the first test as well; which
			// form its one prompt came from was not recorded (delta 1.2, 3.2)
			pairScheme: "talisman://wc?uri={uri_enc}",
			pairBare:   "{uri}",
		},
	},
	{
		// any wallet, by the pairing uri alone: no app is opened and there
		// is no link (design C.3 rule 5)
		walletId:    BittensorWalletWalletConnect,
		displayName: "WalletConnect",
	},
}

// bittensorWalletAppEntryFor is the entry and the platform's links of a wallet
// app, listed or not; nil, nil for another platform or id. Both point into
// the table: read only.
func bittensorWalletAppEntryFor(walletId string, platform string) (*bittensorWalletAppEntry, *bittensorWalletAppLinks) {
	for i := range bittensorWalletApps {
		entry := &bittensorWalletApps[i]
		if entry.walletId != walletId {
			continue
		}
		switch platform {
		case BittensorWalletPlatformIos:
			return entry, &entry.ios
		case BittensorWalletPlatformAndroid:
			return entry, &entry.android
		}
	}
	return nil, nil
}

// bittensorWalletAppLink expands a link template of the table: {uri} is the
// pairing uri as it is, {uri_enc} the uri as one query value,
// {uri_enc_keep_wc} the same with the leading "wc:" left as it is, and
// {request_id} the id of the pending request. What is put in is not expanded
// again. "" for an empty template.
func bittensorWalletAppLink(template string, pairingUri string, requestId int64) string {
	return strings.NewReplacer(
		"{uri}", pairingUri,
		"{uri_enc}", url.QueryEscape(pairingUri),
		"{uri_enc_keep_wc}", "wc:"+url.QueryEscape(strings.TrimPrefix(pairingUri, "wc:")),
		"{request_id}", strconv.FormatInt(requestId, 10),
	).Replace(template)
}

// BittensorWalletChoiceIdList is the wallet chooser of a platform, in display
// order. On macos, windows, linux and web it equals BittensorWalletIdList.
func BittensorWalletChoiceIdList(platform string) *StringList {
	walletIds := NewStringList()
	switch platform {
	case BittensorWalletPlatformMacos, BittensorWalletPlatformWindows, BittensorWalletPlatformLinux, BittensorWalletPlatformWeb:
		return BittensorWalletIdList()
	case BittensorWalletPlatformIos, BittensorWalletPlatformAndroid:
		// the wallet apps listed there, then the wallets of bittensor_wallet.go
		// that sign by copy and paste there (design C.3 rule 1)
		for i := range bittensorWalletApps {
			walletId := bittensorWalletApps[i].walletId
			if _, links := bittensorWalletAppEntryFor(walletId, platform); links.listed {
				walletIds.Add(walletId)
			}
		}
		for _, walletId := range BittensorWalletIdList().values {
			if !walletIds.Contains(walletId) && BittensorWalletTransportFor(walletId, platform) == BittensorWalletTransportManual {
				walletIds.Add(walletId)
			}
		}
	}
	return walletIds
}

// BittensorWalletChoiceFor is the row for a wallet id on a platform, or nil
// when the id is not offered there.
func BittensorWalletChoiceFor(walletId string, platform string) *BittensorWalletChoice {
	if !BittensorWalletChoiceIdList(platform).Contains(walletId) {
		return nil
	}
	choice := &BittensorWalletChoice{
		WalletId:       walletId,
		DisplayName:    BittensorWalletDisplayName(walletId),
		Transport:      BittensorWalletTransportFor(walletId, platform),
		Packages:       NewStringList(),
		PackageSigners: NewStringList(),
	}
	if entry, links := bittensorWalletAppEntryFor(walletId, platform); entry != nil && links.listed {
		choice.DisplayName = entry.displayName
		choice.Transport = BittensorWalletTransportWalletApp
		choice.ProbeUrl = links.probeUrl
		choice.UniversalLinkOnly = links.universalLinkOnly
		choice.Packages.addAll(links.packages...)
		choice.PackageSigners.addAll(links.signers...)
	}
	return choice
}
