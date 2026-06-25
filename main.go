package main

import (
	"context"
	"log"
	"time"

	"DomainC/callback"
	"DomainC/cfclient"
	"DomainC/config"
	"DomainC/internal/app"
	"DomainC/registrarclient"
	"DomainC/reminder"
	"DomainC/scheduler"
	"DomainC/telegram"
)

func main() {
	if err := config.Load("config.yaml"); err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfClient := cfclient.NewClient()
	registrarManager := registrarclient.NewManager(nil, config.Cfg.Registrars)
	var sender telegram.Sender
	botSender, err := telegram.NewBotSender(
		config.Cfg.Telegram.BotToken,
		int64(config.Cfg.Telegram.ChatID),
		2,
		time.Second,
		10*time.Second,
	)
	if err != nil {
		log.Printf("初始化 Telegram 失败，使用空实现: %v", err)
		sender = telegram.NoopSender{}
		telegram.SetDefaultSender(sender)
	} else {
		sender = botSender
	}

	cachePath := config.Cfg.AssetCacheFile
	if cachePath == "" {
		cachePath = reminder.DefaultCachePath
	}
	reminderRuntime := reminder.NewRuntime(reminder.RuntimeOptions{
		Store:        reminder.NewFileStore(cachePath),
		CFClient:     cfClient,
		Accounts:     config.Cfg.CloudflareAccounts,
		Registrar:    registrarManager,
		Whois:        app.DefaultWhoisClient{},
		RefreshDelay: 2 * time.Second,
		QueryTimeout: 15 * time.Second,
		TLS:          10 * time.Second,
	})
	reminder.SetDefaultRuntime(reminderRuntime)
	go reminderRuntime.Run(ctx)

	commandHandler := telegram.NewCommandHandler(cfClient, registrarManager, sender, config.Cfg.CloudflareAccounts, int64(config.Cfg.Telegram.ChatID))

	go func() {
		if err := sender.StartListener(ctx, callback.HandleCallback, commandHandler.HandleMessage); err != nil {
			log.Printf("Telegram 监听停止: %v", err)
		}
	}()

	assetReminder := &app.AssetReminderService{
		Runtime:   reminderRuntime,
		Sender:    sender,
		AlertDays: config.EffectiveAlertDays(),
	}
	sched := scheduler.NewDailyScheduler()
	sched.ScheduleDaily(ctx, 15, 0, func() {
		log.Printf("开始每日到期提醒任务")
		if err := assetReminder.RunDaily(ctx); err != nil {
			log.Printf("每日到期提醒任务失败: %v", err)
		}
	})

	<-ctx.Done()
}
