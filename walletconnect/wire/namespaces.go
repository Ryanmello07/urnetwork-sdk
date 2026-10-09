//go:build !js && !ios_extension

package wire

import (
	"slices"
	"strings"
)

// Namespace is one namespace of a settled session, as the wallet approved it.
// Accounts are CAIP-10 ids ("polkadot:<genesis prefix>:<address>").
type Namespace struct {
	Chains   []string `json:"chains,omitempty"`
	Accounts []string `json:"accounts"`
	Methods  []string `json:"methods"`
	Events   []string `json:"events"`
}

// NamespaceError says why a wallet's namespaces do not satisfy the proposal.
// Code and Message are the specification's (sign/error-codes), fixed text of
// this package: they are what the wallet is answered with.
type NamespaceError struct {
	Code    int
	Message string
}

func (e *NamespaceError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return e.Message
}

// IsCaip2 reports whether s is a CAIP-2 chain id: a namespace of 3 to 8
// characters of [-a-z0-9], a colon, and a reference of 1 to 32 characters of
// [-_a-zA-Z0-9].
func IsCaip2(s string) bool {
	namespace, reference, found := strings.Cut(s, ":")
	return found && isCaip2Namespace(namespace) && isCaip2Reference(reference)
}

// IsCaip10 reports whether s is a CAIP-10 account id: a CAIP-2 chain id, a
// colon, and an address of 1 to 128 characters of [-.%a-zA-Z0-9].
func IsCaip10(s string) bool {
	_, _, ok := splitAccount(s)
	return ok
}

// ValidateNamespaces checks the namespaces of a settled session against a
// proposal that requires one namespace with one chain, one method and no
// event. The checks and their order are the dapp side's in the specification
// (sign/namespaces, cases 2.1 to 2.11), as ur.io's client makes them:
//
//	5000  All namespaces must be approved                  the namespace is missing
//	5001  Accounts must not be empty
//	      for every account, in the order given:
//	5001  Accounts must be CAIP-10 compliant
//	5103  Accounts must be defined in matching namespace   another namespace than the key's
//	5002  All methods must be approved                     method is not listed
//	5001  All chains must have at least one account        no account is on chain
//
// More methods, events, accounts on other chains of the namespace and other
// namespaces are allowed. A namespaceKey that is itself a chain id
// ("eip155:10") is passed as the chain too.
//
// The result is nil when the namespaces satisfy the proposal. It is a
// *NamespaceError and not an error: assigned to an error variable, a nil
// result would no longer compare equal to nil.
func ValidateNamespaces(namespaceKey string, chain string, method string, approved map[string]*Namespace) *NamespaceError {
	namespace := approved[namespaceKey]
	if namespace == nil {
		return &NamespaceError{Code: 5000, Message: "All namespaces must be approved"}
	}
	if len(namespace.Accounts) == 0 {
		return &NamespaceError{Code: 5001, Message: "Accounts must not be empty"}
	}
	keyNamespace, _, _ := strings.Cut(namespaceKey, ":")
	onChain := false
	for _, account := range namespace.Accounts {
		accountChain, _, ok := splitAccount(account)
		if !ok {
			return &NamespaceError{Code: 5001, Message: "Accounts must be CAIP-10 compliant"}
		}
		if accountNamespace, _, _ := strings.Cut(accountChain, ":"); accountNamespace != keyNamespace {
			return &NamespaceError{Code: 5103, Message: "Accounts must be defined in matching namespace"}
		}
		if accountChain == chain {
			onChain = true
		}
	}
	if !slices.Contains(namespace.Methods, method) {
		return &NamespaceError{Code: 5002, Message: "All methods must be approved"}
	}
	if !onChain {
		return &NamespaceError{Code: 5001, Message: "All chains must have at least one account"}
	}
	return nil
}

// ChainAccounts is the accounts of the namespace that are on chain: the
// CAIP-10 ids whose chain id is chain, as the wallet gave them and in its
// order. A wallet may list accounts of other chains of the namespace, before
// or after.
func ChainAccounts(approved map[string]*Namespace, namespaceKey string, chain string) []string {
	namespace := approved[namespaceKey]
	if namespace == nil {
		return nil
	}
	var accounts []string
	for _, account := range namespace.Accounts {
		if accountChain, _, ok := splitAccount(account); ok && accountChain == chain {
			accounts = append(accounts, account)
		}
	}
	return accounts
}

// AccountAddress is the address of a CAIP-10 account id, its third field, or
// "" when account is not one.
func AccountAddress(account string) string {
	_, address, _ := splitAccount(account)
	return address
}

// splitAccount splits a CAIP-10 account id into its chain id and its address.
// Three fields exactly: the address is what follows the last colon, and the
// chain id before it must be a chain id, with one colon of its own.
func splitAccount(account string) (chain string, address string, ok bool) {
	last := strings.LastIndexByte(account, ':')
	if last < 0 {
		return "", "", false
	}
	chain, address = account[:last], account[last+1:]
	if !IsCaip2(chain) || !isCaip10Address(address) {
		return "", "", false
	}
	return chain, address, true
}

// The three character classes are ASCII only, so a length in bytes is a
// length in characters.

func isCaip2Namespace(s string) bool {
	if len(s) < 3 || len(s) > 8 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c == '-' || isLower(c) || isDigit(c)) {
			return false
		}
	}
	return true
}

func isCaip2Reference(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c == '-' || c == '_' || isLower(c) || isUpper(c) || isDigit(c)) {
			return false
		}
	}
	return true
}

func isCaip10Address(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c == '-' || c == '.' || c == '%' || isLower(c) || isUpper(c) || isDigit(c)) {
			return false
		}
	}
	return true
}

func isLower(c byte) bool { return c >= 'a' && c <= 'z' }
func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
