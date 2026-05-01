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

type SetDNSInputStage string

const (
	SetDNSInputKeywords  SetDNSInputStage = "keywords"
	SetDNSInputNewTarget SetDNSInputStage = "new_target"
)

type SetDNSInputRequest struct {
	AccountLabel string
	SessionID    string
	Stage        SetDNSInputStage
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
	SessionID    string
	ItemKey      string
	Page         int
}

type GetNSCallbackPayload struct {
	AccountLabel string
}

type SetDNSCallbackPayload struct {
	AccountLabel string
	SessionID    string
	ItemKey      string
	Page         int
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

type IPListDeleteItem struct {
	Key          string
	AccountLabel string
	ListID       string
	ListName     string
	ItemID       string
	IP           string
	Comment      string
}

type IPListDeleteSelection struct {
	AccountLabel string
	Items        []IPListDeleteItem
	Selected     map[string]bool
	Page         int
}

type SetDNSRecordTarget struct {
	Key       string
	ZoneName  string
	RecordID  string
	Type      string
	Name      string
	Content   string
	TTL       int
	Proxied   *bool
	Matches   []string
}

type SetDNSSelection struct {
	AccountLabel string
	Keywords     []string
	Candidates   []SetDNSRecordTarget
	Selected     map[string]bool
	Page         int
}

var interactionState = struct {
	mu                  sync.Mutex
	pendingIPList       map[int64]IPListInputRequest
	pendingSetDNS       map[int64]SetDNSInputRequest
	pendingGetNS        map[int64]GetNSInputRequest
	pendingDelete       map[int64]DeleteInputRequest
	pendingOriginSSL    map[int64]OriginSSLInputRequest
	originSSLSelections map[int64]OriginSSLSelection
	ipListCallbacks     map[string]IPListCallbackPayload
	ipListDeleteSessions map[string]IPListDeleteSelection
	setDNSCallbacks      map[string]SetDNSCallbackPayload
	setDNSSessions       map[string]SetDNSSelection
	getNSCallbacks      map[string]GetNSCallbackPayload
	deleteCallbacks     map[string]DeleteCallbackPayload
	originSSLCallbacks  map[string]OriginSSLCallbackPayload
}{
	pendingIPList:       make(map[int64]IPListInputRequest),
	pendingSetDNS:       make(map[int64]SetDNSInputRequest),
	pendingGetNS:        make(map[int64]GetNSInputRequest),
	pendingDelete:       make(map[int64]DeleteInputRequest),
	pendingOriginSSL:    make(map[int64]OriginSSLInputRequest),
	originSSLSelections: make(map[int64]OriginSSLSelection),
	ipListCallbacks:     make(map[string]IPListCallbackPayload),
	ipListDeleteSessions: make(map[string]IPListDeleteSelection),
	setDNSCallbacks:      make(map[string]SetDNSCallbackPayload),
	setDNSSessions:       make(map[string]SetDNSSelection),
	getNSCallbacks:      make(map[string]GetNSCallbackPayload),
	deleteCallbacks:     make(map[string]DeleteCallbackPayload),
	originSSLCallbacks:  make(map[string]OriginSSLCallbackPayload),
}

func SetPendingIPListInput(userID int64, req IPListInputRequest) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	delete(interactionState.pendingSetDNS, userID)
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

func SetPendingSetDNSInput(userID int64, req SetDNSInputRequest) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	delete(interactionState.pendingIPList, userID)
	delete(interactionState.pendingGetNS, userID)
	delete(interactionState.pendingDelete, userID)
	delete(interactionState.pendingOriginSSL, userID)
	interactionState.pendingSetDNS[userID] = req
}

func GetPendingSetDNSInput(userID int64) (SetDNSInputRequest, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	req, ok := interactionState.pendingSetDNS[userID]
	return req, ok
}

func ClearPendingSetDNSInput(userID int64) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	delete(interactionState.pendingSetDNS, userID)
}

func SetPendingGetNSInput(userID int64, req GetNSInputRequest) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	delete(interactionState.pendingIPList, userID)
	delete(interactionState.pendingSetDNS, userID)
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
	delete(interactionState.pendingSetDNS, userID)
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
	delete(interactionState.pendingSetDNS, userID)
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

func SetIPListDeleteSelection(selection IPListDeleteSelection) string {
	sessionID := newInteractionToken()
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	interactionState.ipListDeleteSessions[sessionID] = cloneIPListDeleteSelection(selection)
	return sessionID
}

func GetIPListDeleteSelection(sessionID string) (IPListDeleteSelection, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	selection, ok := interactionState.ipListDeleteSessions[sessionID]
	if !ok {
		return IPListDeleteSelection{}, false
	}
	return cloneIPListDeleteSelection(selection), true
}

func ToggleIPListDeleteSelectionItem(sessionID string, key string) (IPListDeleteSelection, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	selection, ok := interactionState.ipListDeleteSessions[sessionID]
	if !ok {
		return IPListDeleteSelection{}, false
	}
	if selection.Selected == nil {
		selection.Selected = make(map[string]bool)
	}
	if selection.Selected[key] {
		delete(selection.Selected, key)
	} else {
		selection.Selected[key] = true
	}
	interactionState.ipListDeleteSessions[sessionID] = selection
	return cloneIPListDeleteSelection(selection), true
}

func SetIPListDeleteSelectionPage(sessionID string, page int) (IPListDeleteSelection, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	selection, ok := interactionState.ipListDeleteSessions[sessionID]
	if !ok {
		return IPListDeleteSelection{}, false
	}
	selection.Page = page
	interactionState.ipListDeleteSessions[sessionID] = selection
	return cloneIPListDeleteSelection(selection), true
}

func SelectedIPListDeleteItems(sessionID string) ([]IPListDeleteItem, bool) {
	selection, ok := GetIPListDeleteSelection(sessionID)
	if !ok {
		return nil, false
	}
	items := make([]IPListDeleteItem, 0, len(selection.Selected))
	for _, item := range selection.Items {
		if selection.Selected[item.Key] {
			items = append(items, item)
		}
	}
	return items, true
}

func ClearIPListDeleteSelection(sessionID string) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	delete(interactionState.ipListDeleteSessions, sessionID)
}

func cloneIPListDeleteSelection(selection IPListDeleteSelection) IPListDeleteSelection {
	out := IPListDeleteSelection{
		AccountLabel: selection.AccountLabel,
		Items:        append([]IPListDeleteItem(nil), selection.Items...),
		Selected:     make(map[string]bool, len(selection.Selected)),
		Page:         selection.Page,
	}
	for key, selected := range selection.Selected {
		out.Selected[key] = selected
	}
	return out
}

func SetSetDNSCallbackPayload(payload SetDNSCallbackPayload) string {
	token := newInteractionToken()
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	interactionState.setDNSCallbacks[token] = payload
	return token
}

func GetSetDNSCallbackPayload(token string) (SetDNSCallbackPayload, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	payload, ok := interactionState.setDNSCallbacks[token]
	return payload, ok
}

func SetSetDNSSelection(selection SetDNSSelection) string {
	sessionID := newInteractionToken()
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	interactionState.setDNSSessions[sessionID] = cloneSetDNSSelection(selection)
	return sessionID
}

func GetSetDNSSelection(sessionID string) (SetDNSSelection, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	selection, ok := interactionState.setDNSSessions[sessionID]
	if !ok {
		return SetDNSSelection{}, false
	}
	return cloneSetDNSSelection(selection), true
}

func ToggleSetDNSSelectionItem(sessionID string, key string) (SetDNSSelection, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	selection, ok := interactionState.setDNSSessions[sessionID]
	if !ok {
		return SetDNSSelection{}, false
	}
	if selection.Selected == nil {
		selection.Selected = make(map[string]bool)
	}
	if selection.Selected[key] {
		delete(selection.Selected, key)
	} else {
		selection.Selected[key] = true
	}
	interactionState.setDNSSessions[sessionID] = selection
	return cloneSetDNSSelection(selection), true
}

func SetSetDNSSelectionPage(sessionID string, page int) (SetDNSSelection, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	selection, ok := interactionState.setDNSSessions[sessionID]
	if !ok {
		return SetDNSSelection{}, false
	}
	selection.Page = page
	interactionState.setDNSSessions[sessionID] = selection
	return cloneSetDNSSelection(selection), true
}

func SelectedSetDNSRecordTargets(sessionID string) ([]SetDNSRecordTarget, bool) {
	selection, ok := GetSetDNSSelection(sessionID)
	if !ok {
		return nil, false
	}
	targets := make([]SetDNSRecordTarget, 0, len(selection.Selected))
	for _, candidate := range selection.Candidates {
		if selection.Selected[candidate.Key] {
			targets = append(targets, candidate)
		}
	}
	return targets, true
}

func RemoveSetDNSRecordTargets(sessionID string, keys []string) (SetDNSSelection, bool) {
	remove := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		remove[key] = struct{}{}
	}

	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	selection, ok := interactionState.setDNSSessions[sessionID]
	if !ok {
		return SetDNSSelection{}, false
	}

	kept := selection.Candidates[:0]
	for _, candidate := range selection.Candidates {
		if _, shouldRemove := remove[candidate.Key]; shouldRemove {
			continue
		}
		kept = append(kept, candidate)
	}
	selection.Candidates = kept
	selection.Selected = make(map[string]bool)
	if selection.Page < 0 {
		selection.Page = 0
	}
	interactionState.setDNSSessions[sessionID] = selection
	return cloneSetDNSSelection(selection), true
}

func ClearSetDNSSelection(sessionID string) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	delete(interactionState.setDNSSessions, sessionID)
}

func cloneSetDNSSelection(selection SetDNSSelection) SetDNSSelection {
	out := SetDNSSelection{
		AccountLabel: selection.AccountLabel,
		Keywords:     append([]string(nil), selection.Keywords...),
		Candidates:   append([]SetDNSRecordTarget(nil), selection.Candidates...),
		Selected:     make(map[string]bool, len(selection.Selected)),
		Page:         selection.Page,
	}
	for key, selected := range selection.Selected {
		out.Selected[key] = selected
	}
	return out
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
