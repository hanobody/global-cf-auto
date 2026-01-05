package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	AlertDays          int      `yaml:"alertDays"`
	Telegram           Telegram `yaml:"telegram"`
	CloudflareAccounts []CF     `yaml:"cloudflareAccounts"`
	DomainFiles        []string `yaml:"domainFiles"`
}

type Telegram struct {
	BotToken string `yaml:"botToken"`
	ChatID   int64  `yaml:"chatID"`
}

type CF struct {
	Label     string `yaml:"label"`
	Email     string `yaml:"email"`
	APIToken  string `yaml:"apiToken"`
	AccountID string `yaml:"accountID"`
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
	return nil
}
