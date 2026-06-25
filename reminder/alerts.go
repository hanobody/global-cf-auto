package reminder

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const DefaultAlertDays = 7

type AlertType string

const (
	AlertTypeDomainExpiry AlertType = "domain_expiry"
	AlertTypeCertificate  AlertType = "certificate_expiry"
)

type Alert struct {
	Key         string
	Type        AlertType
	Domain      string
	Source      string
	Expiry      time.Time
	DaysLeft    int
	CertType    string
	CertID      string
	Issuer      string
	Subject     string
	Hostnames   []string
	Description string
}

func EffectiveAlertDays(days int) int {
	if days <= 0 {
		return DefaultAlertDays
	}
	return days
}

func (r *Runtime) DueAlerts(alertDays int, now time.Time) ([]Alert, error) {
	if r == nil || r.store == nil {
		return nil, nil
	}
	alertDays = EffectiveAlertDays(alertDays)
	if now.IsZero() {
		now = time.Now()
	}
	c, err := r.store.Load()
	if err != nil {
		return nil, err
	}
	today := now.Format("2006-01-02")
	var alerts []Alert
	for _, rec := range c.Records {
		if rec == nil || rec.Deleted || NormalizeDomain(rec.Domain) == "" {
			continue
		}
		if t, ok := parseDate(rec.DomainExpiry); ok {
			daysLeft := daysUntil(t, now)
			if daysLeft <= alertDays && strings.TrimSpace(rec.DomainLastAlertDate) != today {
				alerts = append(alerts, Alert{
					Key:      domainAlertKey(rec.Source, rec.Domain),
					Type:     AlertTypeDomainExpiry,
					Domain:   rec.Domain,
					Source:   rec.Source,
					Expiry:   t,
					DaysLeft: daysLeft,
				})
			}
		}
		for _, cert := range rec.Certificates {
			if t, ok := parseTimeValue(cert.NotAfter); ok {
				daysLeft := daysUntil(t, now)
				if daysLeft <= alertDays && strings.TrimSpace(cert.LastAlertDate) != today {
					alerts = append(alerts, Alert{
						Key:         certificateAlertKey(rec.Source, rec.Domain, cert),
						Type:        AlertTypeCertificate,
						Domain:      rec.Domain,
						Source:      rec.Source,
						Expiry:      t,
						DaysLeft:    daysLeft,
						CertType:    cert.Type,
						CertID:      cert.ID,
						Issuer:      cert.Issuer,
						Subject:     cert.Subject,
						Hostnames:   append([]string(nil), cert.Hostnames...),
						Description: certificateDescription(cert),
					})
				}
			}
		}
	}
	sort.Slice(alerts, func(i, j int) bool {
		if alerts[i].Expiry.Equal(alerts[j].Expiry) {
			return alerts[i].Domain < alerts[j].Domain
		}
		return alerts[i].Expiry.Before(alerts[j].Expiry)
	})
	return alerts, nil
}

func (r *Runtime) MarkAlertsSent(alerts []Alert, now time.Time) error {
	if r == nil || r.store == nil || len(alerts) == 0 {
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	today := now.Format("2006-01-02")
	byKey := map[string]Alert{}
	for _, alert := range alerts {
		byKey[alert.Key] = alert
	}
	return r.store.SaveWithMutation(func(c *Cache) {
		for _, rec := range c.Records {
			if rec == nil {
				continue
			}
			if _, ok := byKey[domainAlertKey(rec.Source, rec.Domain)]; ok {
				rec.DomainLastAlertDate = today
				rec.UpdatedAt = now.Format(time.RFC3339)
			}
			for i := range rec.Certificates {
				key := certificateAlertKey(rec.Source, rec.Domain, rec.Certificates[i])
				if _, ok := byKey[key]; ok {
					rec.Certificates[i].LastAlertDate = today
					rec.Certificates[i].UpdatedAt = now.Format(time.RFC3339)
				}
			}
		}
	})
}

func (s *Store) SaveWithMutation(fn func(*Cache)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.loadLocked()
	if err != nil {
		return err
	}
	fn(&c)
	return s.saveLocked(c)
}

func domainAlertKey(source string, domain string) string {
	return "domain|" + RecordKey(source, domain)
}

func certificateAlertKey(source string, domain string, cert CertificateRecord) string {
	return fmt.Sprintf("cert|%s|%s", RecordKey(source, domain), certificateKey(cert))
}

func certificateDescription(cert CertificateRecord) string {
	switch cert.Type {
	case CertTypeCFOrigin:
		return "Cloudflare Origin CA 源站证书"
	case CertTypeServed:
		issuer := strings.ToLower(cert.Issuer)
		if strings.Contains(issuer, "cloudflare") {
			return "当前访问证书/Cloudflare 边缘证书"
		}
		return "当前访问证书/三方签发证书"
	default:
		return "SSL 证书"
	}
}
