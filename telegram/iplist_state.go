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

type IPListCallbackPayload struct {
	AccountLabel string
	ListID       string
	ListName     string
	ItemID       string
}

type GetNSCallbackPayload struct {
	AccountLabel string
}

var interactionState = struct {
	mu              sync.Mutex
	pendingIPList   map[int64]IPListInputRequest
	pendingGetNS    map[int64]GetNSInputRequest
	ipListCallbacks map[string]IPListCallbackPayload
	getNSCallbacks  map[string]GetNSCallbackPayload
}{
	pendingIPList:   make(map[int64]IPListInputRequest),
	pendingGetNS:    make(map[int64]GetNSInputRequest),
	ipListCallbacks: make(map[string]IPListCallbackPayload),
	getNSCallbacks:  make(map[string]GetNSCallbackPayload),
}

func SetPendingIPListInput(userID int64, req IPListInputRequest) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	delete(interactionState.pendingGetNS, userID)
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

func newInteractionToken() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return hex.EncodeToString([]byte("fallback"))
	}
	return hex.EncodeToString(buf)
}
