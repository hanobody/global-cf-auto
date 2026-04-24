package telegram

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
)

type IPListAction string

const (
	IPListActionAdd    IPListAction = "add"
	IPListActionDelete IPListAction = "delete"
)

type IPListInputRequest struct {
	AccountLabel string
	ListID       string
	ListName     string
	Action       IPListAction
}

type GetNSInputRequest struct {
	AccountLabel string
}

type DeleteInputRequest struct {
	AccountLabel string
}

type OriginSSLInputRequest struct {
	AWSAliases []string
}

type IPListCallbackPayload struct {
	AccountLabel string
	ListID       string
	ListName     string
	ItemID       string
}

type GetNSCallbackPayload struct {
	AccountLabel string
}

type DeleteCallbackPayload struct {
	AccountLabel string
	Domains      []string
	ParseErrors  []string
}

type OriginSSLSelection struct {
	AWSAliases map[string]bool
}

type OriginSSLCallbackPayload struct {
	Value string
}

var interactionState = struct {
	mu                  sync.Mutex
	pendingIPList       map[int64]IPListInputRequest
	pendingGetNS        map[int64]GetNSInputRequest
	pendingDelete       map[int64]DeleteInputRequest
	pendingOriginSSL    map[int64]OriginSSLInputRequest
	originSSLSelections map[int64]OriginSSLSelection
	ipListCallbacks     map[string]IPListCallbackPayload
	getNSCallbacks      map[string]GetNSCallbackPayload
	deleteCallbacks     map[string]DeleteCallbackPayload
	originSSLCallbacks  map[string]OriginSSLCallbackPayload
}{
	pendingIPList:       make(map[int64]IPListInputRequest),
	pendingGetNS:        make(map[int64]GetNSInputRequest),
	pendingDelete:       make(map[int64]DeleteInputRequest),
	pendingOriginSSL:    make(map[int64]OriginSSLInputRequest),
	originSSLSelections: make(map[int64]OriginSSLSelection),
	ipListCallbacks:     make(map[string]IPListCallbackPayload),
	getNSCallbacks:      make(map[string]GetNSCallbackPayload),
	deleteCallbacks:     make(map[string]DeleteCallbackPayload),
	originSSLCallbacks:  make(map[string]OriginSSLCallbackPayload),
}

func SetPendingIPListInput(userID int64, req IPListInputRequest) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	delete(interactionState.pendingGetNS, userID)
	delete(interactionState.pendingDelete, userID)
	delete(interactionState.pendingOriginSSL, userID)
	interactionState.pendingIPList[userID] = req
}

func GetPendingIPListInput(userID int64) (IPListInputRequest, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	req, ok := interactionState.pendingIPList[userID]
	return req, ok
}

func ClearPendingIPListInput(userID int64) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	delete(interactionState.pendingIPList, userID)
}

func SetPendingGetNSInput(userID int64, req GetNSInputRequest) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	delete(interactionState.pendingIPList, userID)
	delete(interactionState.pendingDelete, userID)
	delete(interactionState.pendingOriginSSL, userID)
	interactionState.pendingGetNS[userID] = req
}

func GetPendingGetNSInput(userID int64) (GetNSInputRequest, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	req, ok := interactionState.pendingGetNS[userID]
	return req, ok
}

func ClearPendingGetNSInput(userID int64) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	delete(interactionState.pendingGetNS, userID)
}

func SetPendingDeleteInput(userID int64, req DeleteInputRequest) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	delete(interactionState.pendingIPList, userID)
	delete(interactionState.pendingGetNS, userID)
	delete(interactionState.pendingOriginSSL, userID)
	interactionState.pendingDelete[userID] = req
}

func GetPendingDeleteInput(userID int64) (DeleteInputRequest, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	req, ok := interactionState.pendingDelete[userID]
	return req, ok
}

func ClearPendingDeleteInput(userID int64) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	delete(interactionState.pendingDelete, userID)
}

func SetPendingOriginSSLInput(userID int64, req OriginSSLInputRequest) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	delete(interactionState.pendingIPList, userID)
	delete(interactionState.pendingGetNS, userID)
	delete(interactionState.pendingDelete, userID)
	interactionState.pendingOriginSSL[userID] = OriginSSLInputRequest{
		AWSAliases: append([]string(nil), req.AWSAliases...),
	}
}

func GetPendingOriginSSLInput(userID int64) (OriginSSLInputRequest, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	req, ok := interactionState.pendingOriginSSL[userID]
	if !ok {
		return OriginSSLInputRequest{}, false
	}
	return OriginSSLInputRequest{
		AWSAliases: append([]string(nil), req.AWSAliases...),
	}, true
}

func ClearPendingOriginSSLInput(userID int64) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	delete(interactionState.pendingOriginSSL, userID)
}

func ResetOriginSSLSelection(userID int64) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	delete(interactionState.pendingOriginSSL, userID)
	interactionState.originSSLSelections[userID] = OriginSSLSelection{
		AWSAliases: make(map[string]bool),
	}
}

func GetOriginSSLSelection(userID int64) OriginSSLSelection {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	return cloneOriginSSLSelection(ensureOriginSSLSelectionLocked(userID))
}

func ToggleOriginSSLAlias(userID int64, alias string) OriginSSLSelection {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	selection := ensureOriginSSLSelectionLocked(userID)
	if selection.AWSAliases[alias] {
		delete(selection.AWSAliases, alias)
	} else {
		selection.AWSAliases[alias] = true
	}
	return cloneOriginSSLSelection(selection)
}

func ensureOriginSSLSelectionLocked(userID int64) OriginSSLSelection {
	selection, ok := interactionState.originSSLSelections[userID]
	if !ok {
		selection = OriginSSLSelection{
			AWSAliases: make(map[string]bool),
		}
		interactionState.originSSLSelections[userID] = selection
		return selection
	}
	if selection.AWSAliases == nil {
		selection.AWSAliases = make(map[string]bool)
	}
	interactionState.originSSLSelections[userID] = selection
	return selection
}

func cloneOriginSSLSelection(selection OriginSSLSelection) OriginSSLSelection {
	out := OriginSSLSelection{
		AWSAliases: make(map[string]bool, len(selection.AWSAliases)),
	}
	for alias, ok := range selection.AWSAliases {
		out.AWSAliases[alias] = ok
	}
	return out
}

func SetIPListCallbackPayload(payload IPListCallbackPayload) string {
	token := newInteractionToken()
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	interactionState.ipListCallbacks[token] = payload
	return token
}

func GetIPListCallbackPayload(token string) (IPListCallbackPayload, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	payload, ok := interactionState.ipListCallbacks[token]
	return payload, ok
}

func SetGetNSCallbackPayload(payload GetNSCallbackPayload) string {
	token := newInteractionToken()
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	interactionState.getNSCallbacks[token] = payload
	return token
}

func GetGetNSCallbackPayload(token string) (GetNSCallbackPayload, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	payload, ok := interactionState.getNSCallbacks[token]
	return payload, ok
}

func SetDeleteCallbackPayload(payload DeleteCallbackPayload) string {
	token := newInteractionToken()
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	interactionState.deleteCallbacks[token] = DeleteCallbackPayload{
		AccountLabel: payload.AccountLabel,
		Domains:      append([]string(nil), payload.Domains...),
		ParseErrors:  append([]string(nil), payload.ParseErrors...),
	}
	return token
}

func GetDeleteCallbackPayload(token string) (DeleteCallbackPayload, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	payload, ok := interactionState.deleteCallbacks[token]
	if !ok {
		return DeleteCallbackPayload{}, false
	}
	return DeleteCallbackPayload{
		AccountLabel: payload.AccountLabel,
		Domains:      append([]string(nil), payload.Domains...),
		ParseErrors:  append([]string(nil), payload.ParseErrors...),
	}, true
}

func SetOriginSSLCallbackPayload(payload OriginSSLCallbackPayload) string {
	token := newInteractionToken()
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	interactionState.originSSLCallbacks[token] = payload
	return token
}

func GetOriginSSLCallbackPayload(token string) (OriginSSLCallbackPayload, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	payload, ok := interactionState.originSSLCallbacks[token]
	return payload, ok
}

func newInteractionToken() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return hex.EncodeToString([]byte("fallback"))
	}
	return hex.EncodeToString(buf)
}
