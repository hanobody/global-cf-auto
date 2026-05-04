package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	AlertDays          int         `yaml:"alertDays"`
	Telegram           Telegram    `yaml:"telegram"`
	CloudflareAccounts []CF        `yaml:"cloudflareAccounts"`
	CloudflareProvision CFProvision `yaml:"cloudflareProvision"`
	Registrars         []Registrar `yaml:"registrars"`
	DomainFiles        []string    `yaml:"domainFiles"`

	AWSTargets map[string]AWSTarget `yaml:"awsTargets"`
}

type Telegram struct {
	BotToken       string  `yaml:"botToken"`
	ChatID         int64   `yaml:"chatID"`
	AllowedChatIDs []int64 `yaml:"allowedChatIds"`
}

type CF struct {
	Label     string `yaml:"label"`
	Email     string `yaml:"email"`
	APIToken  string `yaml:"apiToken"`
	AccountID string `yaml:"accountID"`
}

type CFProvision struct {
	DefaultBlockCountries      string `yaml:"defaultBlockCountries"`
	EnableSpeedRecommendations *bool  `yaml:"enableSpeedRecommendations"`
	EnableRUMAutoInstall       *bool  `yaml:"enableRumAutoInstall"`
	EnableCacheRule            *bool  `yaml:"enableCacheRule"`
	ExtraZoneSettings          string `yaml:"extraZoneSettings"`
}
type Registrar struct {
	Label     string           `yaml:"label"`
	Type      string           `yaml:"type"`
	Namecheap *NamecheapConfig `yaml:"namecheap"`
	GoDaddy   *GoDaddyConfig   `yaml:"godaddy"`
}

type NamecheapConfig struct {
	User     string `yaml:"user"`
	APIKey   string `yaml:"apiKey"`
	ClientIP string `yaml:"clientIP"`
}

type GoDaddyConfig struct {
	APIKey    string `yaml:"apiKey"`
	APISecret string `yaml:"apiSecret"`
}
type AWSCreds struct {
	AccessKeyID     string `yaml:"accessKeyId"`
	SecretAccessKey string `yaml:"secretAccessKey"`
	SessionToken    string `yaml:"sessionToken"`
}

type AWSTarget struct {
	Region string   `yaml:"region"`
	Creds  AWSCreds `yaml:"creds"`
}

var Cfg Config

func Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %w", err)
	}
	if err := yaml.Unmarshal(data, &Cfg); err != nil {
		return fmt.Errorf("解析配置失败: %w", err)
	}
	applyEnvOverrides()
	return nil
}

func applyEnvOverrides() {
	if token := strings.TrimSpace(os.Getenv("CLOUDFLARE_API_TOKEN")); token != "" {
		accountID := strings.TrimSpace(os.Getenv("CLOUDFLARE_ACCOUNT_ID"))
		if len(Cfg.CloudflareAccounts) == 0 {
			Cfg.CloudflareAccounts = append(Cfg.CloudflareAccounts, CF{
				Label:     "env",
				APIToken:  token,
				AccountID: accountID,
			})
		} else {
			if strings.TrimSpace(Cfg.CloudflareAccounts[0].APIToken) == "" {
				Cfg.CloudflareAccounts[0].APIToken = token
			}
			if accountID != "" && strings.TrimSpace(Cfg.CloudflareAccounts[0].AccountID) == "" {
				Cfg.CloudflareAccounts[0].AccountID = accountID
			}
		}
	}

	if value := strings.TrimSpace(os.Getenv("CF_DEFAULT_BLOCK_COUNTRIES")); value != "" {
		Cfg.CloudflareProvision.DefaultBlockCountries = value
	}
	if value := strings.TrimSpace(os.Getenv("CF_ENABLE_SPEED_RECOMMENDATIONS")); value != "" {
		if parsed, ok := parseBool(value); ok {
			Cfg.CloudflareProvision.EnableSpeedRecommendations = &parsed
		}
	}
	if value := strings.TrimSpace(os.Getenv("CF_ENABLE_RUM_AUTO_INSTALL")); value != "" {
		if parsed, ok := parseBool(value); ok {
			Cfg.CloudflareProvision.EnableRUMAutoInstall = &parsed
		}
	}
	if value := strings.TrimSpace(os.Getenv("CF_ENABLE_CACHE_RULE")); value != "" {
		if parsed, ok := parseBool(value); ok {
			Cfg.CloudflareProvision.EnableCacheRule = &parsed
		}
	}
	if value := strings.TrimSpace(os.Getenv("CF_EXTRA_ZONE_SETTINGS")); value != "" {
		Cfg.CloudflareProvision.ExtraZoneSettings = value
	}
	if value := strings.TrimSpace(os.Getenv("TELEGRAM_ALLOWED_CHAT_IDS")); value != "" {
		Cfg.Telegram.AllowedChatIDs = parseInt64List(value)
	}
}

func DefaultBlockCountries() []string {
	return splitConfigList(Cfg.CloudflareProvision.DefaultBlockCountries)
}

func EnableSpeedRecommendations() bool {
	if Cfg.CloudflareProvision.EnableSpeedRecommendations == nil {
		return true
	}
	return *Cfg.CloudflareProvision.EnableSpeedRecommendations
}

func EnableRUMAutoInstall() bool {
	if Cfg.CloudflareProvision.EnableRUMAutoInstall == nil {
		return true
	}
	return *Cfg.CloudflareProvision.EnableRUMAutoInstall
}

func EnableCacheRule() bool {
	if Cfg.CloudflareProvision.EnableCacheRule == nil {
		return true
	}
	return *Cfg.CloudflareProvision.EnableCacheRule
}

func ExtraZoneSettings() map[string]any {
	raw := strings.TrimSpace(Cfg.CloudflareProvision.ExtraZoneSettings)
	if raw == "" {
		return nil
	}
	if strings.HasPrefix(raw, "{") {
		var out map[string]any
		if err := json.Unmarshal([]byte(raw), &out); err == nil {
			return out
		}
	}

	out := map[string]any{}
	for _, item := range splitConfigList(raw) {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" || value == "" {
			continue
		}
		out[key] = value
	}
	return out
}

func IsTelegramChatAllowed(chatID int64) bool {
	if len(Cfg.Telegram.AllowedChatIDs) > 0 {
		for _, allowed := range Cfg.Telegram.AllowedChatIDs {
			if allowed == chatID {
				return true
			}
		}
		return false
	}
	if Cfg.Telegram.ChatID == 0 {
		return true
	}
	return Cfg.Telegram.ChatID == chatID
}

func splitConfigList(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field != "" {
			out = append(out, field)
		}
	}
	return out
}

func parseBool(raw string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "y", "on", "enable", "enabled":
		return true, true
	case "0", "false", "no", "n", "off", "disable", "disabled":
		return false, true
	default:
		return false, false
	}
}

func parseInt64List(raw string) []int64 {
	items := splitConfigList(raw)
	out := make([]int64, 0, len(items))
	for _, item := range items {
		value, err := strconv.ParseInt(item, 10, 64)
		if err == nil {
			out = append(out, value)
		}
	}
	return out
}
