package telegram

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
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

type GetNSInputStage string

const (
	GetNSInputDomains        GetNSInputStage = "domains"
	GetNSInputBlockCountries GetNSInputStage = "block_countries"
)

type GetNSInputRequest struct {
	AccountLabel   string
	Stage          GetNSInputStage
	EnableSecurity bool
	EnableSpeed    bool
	EnableCache    bool
	EnableRUM      bool
	BlockCountries []string
}

type DeleteInputRequest struct {
	AccountLabel string
}

type OriginSSLInputStage string

const (
	OriginSSLInputDomains    OriginSSLInputStage = "domains"
	OriginSSLInputBlockCountries OriginSSLInputStage = "block_countries"
	OriginSSLInputDNSTarget  OriginSSLInputStage = "dns_target"
	OriginSSLInputDNSRecords OriginSSLInputStage = "dns_records"
)

type OriginSSLInputRequest struct {
	AWSAliases       []string
	AccountLabel     string
	SessionID        string
	Stage            OriginSSLInputStage
	DNSTarget        string
	DNSRecordType    string
	Proxied          bool
	SelectedDomains  []string
	BlockCountries   []string
	PendingDNSRecords []OriginSSLDNSRecordPlan
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
	AccountLabel   string
	EnableSecurity bool
	EnableSpeed    bool
	EnableCache    bool
	EnableRUM      bool
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
	Value         string
	AccountLabel  string
	SessionID     string
	ItemKey       string
	Page          int
	DNSTarget     string
	DNSRecordType string
	Proxied       bool
}

type OriginSSLDomainItem struct {
	Key              string
	AccountLabel     string
	ZoneID           string
	Name             string
	Status           string
	Paused           bool
	CreatedOn        time.Time
	Plan             string
	SecurityInsights string
	UniqueVisitors   string
}

type OriginSSLDomainSelection struct {
	AccountLabel string
	Items        []OriginSSLDomainItem
	Selected     map[string]bool
	AWSAliases   map[string]bool
	BlockCountries []string
	Page         int
}

type OriginSSLDNSRecordPlan struct {
	AccountLabel string
	Domain       string
	Name         string
	FQDN         string
	Type         string
	Content      string
	Proxied      bool
	AutoWWW      bool
}

type OriginSSLDNSPlan struct {
	AccountLabel string
	SessionID    string
	Records      []OriginSSLDNSRecordPlan
}

type OriginSSLDNSNameSelection struct {
	AccountLabel      string
	OriginSessionID   string
	DNSTarget         string
	DNSRecordType     string
	Proxied           bool
	Names             []string
	Domains           []string
	Selected          map[string]bool
	PendingDNSRecords []OriginSSLDNSRecordPlan
	Page              int
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
	originSSLDomains    map[string]OriginSSLDomainSelection
	originSSLDNSPlans   map[string]OriginSSLDNSPlan
	originSSLDNSNames   map[string]OriginSSLDNSNameSelection
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
	originSSLDomains:    make(map[string]OriginSSLDomainSelection),
	originSSLDNSPlans:   make(map[string]OriginSSLDNSPlan),
	originSSLDNSNames:   make(map[string]OriginSSLDNSNameSelection),
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
	if req.Stage == "" {
		req.Stage = GetNSInputDomains
	}
	req.BlockCountries = append([]string(nil), req.BlockCountries...)
	interactionState.pendingGetNS[userID] = req
}

func GetPendingGetNSInput(userID int64) (GetNSInputRequest, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	req, ok := interactionState.pendingGetNS[userID]
	req.BlockCountries = append([]string(nil), req.BlockCountries...)
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
		AWSAliases:       append([]string(nil), req.AWSAliases...),
		AccountLabel:     req.AccountLabel,
		SessionID:        req.SessionID,
		Stage:            req.Stage,
		DNSTarget:        req.DNSTarget,
		DNSRecordType:    req.DNSRecordType,
		Proxied:          req.Proxied,
		SelectedDomains:  append([]string(nil), req.SelectedDomains...),
		BlockCountries:   append([]string(nil), req.BlockCountries...),
		PendingDNSRecords: append([]OriginSSLDNSRecordPlan(nil), req.PendingDNSRecords...),
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
		AWSAliases:       append([]string(nil), req.AWSAliases...),
		AccountLabel:     req.AccountLabel,
		SessionID:        req.SessionID,
		Stage:            req.Stage,
		DNSTarget:        req.DNSTarget,
		DNSRecordType:    req.DNSRecordType,
		Proxied:          req.Proxied,
		SelectedDomains:  append([]string(nil), req.SelectedDomains...),
		BlockCountries:   append([]string(nil), req.BlockCountries...),
		PendingDNSRecords: append([]OriginSSLDNSRecordPlan(nil), req.PendingDNSRecords...),
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

func SetOriginSSLDomainSelection(selection OriginSSLDomainSelection) string {
	sessionID := newInteractionToken()
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	interactionState.originSSLDomains[sessionID] = cloneOriginSSLDomainSelection(selection)
	return sessionID
}

func GetOriginSSLDomainSelection(sessionID string) (OriginSSLDomainSelection, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	selection, ok := interactionState.originSSLDomains[sessionID]
	if !ok {
		return OriginSSLDomainSelection{}, false
	}
	return cloneOriginSSLDomainSelection(selection), true
}

func ToggleOriginSSLDomainSelectionItem(sessionID string, key string) (OriginSSLDomainSelection, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	selection, ok := interactionState.originSSLDomains[sessionID]
	if !ok {
		return OriginSSLDomainSelection{}, false
	}
	if selection.Selected == nil {
		selection.Selected = make(map[string]bool)
	}
	if selection.Selected[key] {
		delete(selection.Selected, key)
	} else {
		selection.Selected[key] = true
	}
	interactionState.originSSLDomains[sessionID] = selection
	return cloneOriginSSLDomainSelection(selection), true
}

func ToggleOriginSSLDomainAWSAlias(sessionID string, alias string) (OriginSSLDomainSelection, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	selection, ok := interactionState.originSSLDomains[sessionID]
	if !ok {
		return OriginSSLDomainSelection{}, false
	}
	if selection.AWSAliases == nil {
		selection.AWSAliases = make(map[string]bool)
	}
	if selection.AWSAliases[alias] {
		delete(selection.AWSAliases, alias)
	} else {
		selection.AWSAliases[alias] = true
	}
	interactionState.originSSLDomains[sessionID] = selection
	return cloneOriginSSLDomainSelection(selection), true
}

func SetOriginSSLDomainBlockCountries(sessionID string, countries []string) (OriginSSLDomainSelection, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	selection, ok := interactionState.originSSLDomains[sessionID]
	if !ok {
		return OriginSSLDomainSelection{}, false
	}
	selection.BlockCountries = append([]string(nil), countries...)
	interactionState.originSSLDomains[sessionID] = selection
	return cloneOriginSSLDomainSelection(selection), true
}

func SetOriginSSLDomainSelectionPage(sessionID string, page int) (OriginSSLDomainSelection, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	selection, ok := interactionState.originSSLDomains[sessionID]
	if !ok {
		return OriginSSLDomainSelection{}, false
	}
	selection.Page = page
	interactionState.originSSLDomains[sessionID] = selection
	return cloneOriginSSLDomainSelection(selection), true
}

func SelectedOriginSSLDomainItems(sessionID string) ([]OriginSSLDomainItem, bool) {
	selection, ok := GetOriginSSLDomainSelection(sessionID)
	if !ok {
		return nil, false
	}
	items := make([]OriginSSLDomainItem, 0, len(selection.Selected))
	for _, item := range selection.Items {
		if selection.Selected[item.Key] {
			items = append(items, item)
		}
	}
	return items, true
}

func ClearOriginSSLDomainSelection(sessionID string) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	delete(interactionState.originSSLDomains, sessionID)
}

func cloneOriginSSLDomainSelection(selection OriginSSLDomainSelection) OriginSSLDomainSelection {
	out := OriginSSLDomainSelection{
		AccountLabel: selection.AccountLabel,
		Items:        append([]OriginSSLDomainItem(nil), selection.Items...),
		Selected:     make(map[string]bool, len(selection.Selected)),
		AWSAliases:   make(map[string]bool, len(selection.AWSAliases)),
		BlockCountries: append([]string(nil), selection.BlockCountries...),
		Page:         selection.Page,
	}
	for key, selected := range selection.Selected {
		out.Selected[key] = selected
	}
	for alias, selected := range selection.AWSAliases {
		out.AWSAliases[alias] = selected
	}
	return out
}

func SetOriginSSLDNSPlan(plan OriginSSLDNSPlan) string {
	planID := newInteractionToken()
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	interactionState.originSSLDNSPlans[planID] = OriginSSLDNSPlan{
		AccountLabel: plan.AccountLabel,
		SessionID:    plan.SessionID,
		Records:      append([]OriginSSLDNSRecordPlan(nil), plan.Records...),
	}
	return planID
}

func GetOriginSSLDNSPlan(planID string) (OriginSSLDNSPlan, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	plan, ok := interactionState.originSSLDNSPlans[planID]
	if !ok {
		return OriginSSLDNSPlan{}, false
	}
	return OriginSSLDNSPlan{
		AccountLabel: plan.AccountLabel,
		SessionID:    plan.SessionID,
		Records:      append([]OriginSSLDNSRecordPlan(nil), plan.Records...),
	}, true
}

func ClearOriginSSLDNSPlan(planID string) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	delete(interactionState.originSSLDNSPlans, planID)
}

func SetOriginSSLDNSNameSelection(selection OriginSSLDNSNameSelection) string {
	sessionID := newInteractionToken()
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	interactionState.originSSLDNSNames[sessionID] = cloneOriginSSLDNSNameSelection(selection)
	return sessionID
}

func GetOriginSSLDNSNameSelection(sessionID string) (OriginSSLDNSNameSelection, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	selection, ok := interactionState.originSSLDNSNames[sessionID]
	if !ok {
		return OriginSSLDNSNameSelection{}, false
	}
	return cloneOriginSSLDNSNameSelection(selection), true
}

func ToggleOriginSSLDNSNameSelectionDomain(sessionID string, domain string) (OriginSSLDNSNameSelection, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	selection, ok := interactionState.originSSLDNSNames[sessionID]
	if !ok {
		return OriginSSLDNSNameSelection{}, false
	}
	if selection.Selected == nil {
		selection.Selected = make(map[string]bool)
	}
	if selection.Selected[domain] {
		delete(selection.Selected, domain)
	} else {
		selection.Selected[domain] = true
	}
	interactionState.originSSLDNSNames[sessionID] = selection
	return cloneOriginSSLDNSNameSelection(selection), true
}

func SetOriginSSLDNSNameSelectionPage(sessionID string, page int) (OriginSSLDNSNameSelection, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	selection, ok := interactionState.originSSLDNSNames[sessionID]
	if !ok {
		return OriginSSLDNSNameSelection{}, false
	}
	selection.Page = page
	interactionState.originSSLDNSNames[sessionID] = selection
	return cloneOriginSSLDNSNameSelection(selection), true
}

func SelectAllOriginSSLDNSNameDomains(sessionID string) (OriginSSLDNSNameSelection, bool) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	selection, ok := interactionState.originSSLDNSNames[sessionID]
	if !ok {
		return OriginSSLDNSNameSelection{}, false
	}
	if selection.Selected == nil {
		selection.Selected = make(map[string]bool, len(selection.Domains))
	}
	for _, domain := range selection.Domains {
		selection.Selected[domain] = true
	}
	interactionState.originSSLDNSNames[sessionID] = selection
	return cloneOriginSSLDNSNameSelection(selection), true
}

func SelectedOriginSSLDNSNameDomains(sessionID string) ([]string, bool) {
	selection, ok := GetOriginSSLDNSNameSelection(sessionID)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(selection.Selected))
	for _, domain := range selection.Domains {
		if selection.Selected[domain] {
			out = append(out, domain)
		}
	}
	return out, true
}

func ClearOriginSSLDNSNameSelection(sessionID string) {
	interactionState.mu.Lock()
	defer interactionState.mu.Unlock()
	delete(interactionState.originSSLDNSNames, sessionID)
}

func cloneOriginSSLDNSNameSelection(selection OriginSSLDNSNameSelection) OriginSSLDNSNameSelection {
	out := OriginSSLDNSNameSelection{
		AccountLabel:      selection.AccountLabel,
		OriginSessionID:   selection.OriginSessionID,
		DNSTarget:         selection.DNSTarget,
		DNSRecordType:     selection.DNSRecordType,
		Proxied:           selection.Proxied,
		Names:             append([]string(nil), selection.Names...),
		Domains:           append([]string(nil), selection.Domains...),
		Selected:          make(map[string]bool, len(selection.Selected)),
		PendingDNSRecords: append([]OriginSSLDNSRecordPlan(nil), selection.PendingDNSRecords...),
		Page:              selection.Page,
	}
	for key, selected := range selection.Selected {
		out.Selected[key] = selected
	}
	return out
}

func newInteractionToken() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return hex.EncodeToString([]byte("fallback"))
	}
	return hex.EncodeToString(buf)
}
