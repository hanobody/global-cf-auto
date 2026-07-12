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
	botSender, err := telegram.NewMultiBotSender(
		config.Cfg.Telegram.BotToken,
		config.TelegramChatIDs(),
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
	go func() {
		log.Printf("开始启动资产缓存同步")
		summary := reminderRuntime.SyncCloudflareDomainsOnce(ctx)
		if len(summary.Errors) > 0 {
			log.Printf("启动资产缓存同步完成但存在错误: accounts=%d/%d domains=%d added=%d updated=%d unknown=%d queued=%d errors=%v",
				summary.ScannedAccounts, summary.ConfiguredAccounts, summary.DomainsSeen, summary.Added, summary.Updated, summary.MarkedUnknown, summary.QueuedRefresh, summary.Errors)
			return
		}
		log.Printf("启动资产缓存同步完成: accounts=%d/%d domains=%d added=%d updated=%d unknown=%d queued=%d",
			summary.ScannedAccounts, summary.ConfiguredAccounts, summary.DomainsSeen, summary.Added, summary.Updated, summary.MarkedUnknown, summary.QueuedRefresh)
	}()

	commandHandler := telegram.NewCommandHandler(cfClient, registrarManager, sender, config.Cfg.CloudflareAccounts, 0)

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

	if config.AbuseReportEnabled() {
		abuseReportService := &app.AbuseReportService{
			CFClient:  cfClient,
			Accounts:  config.Cfg.CloudflareAccounts,
			Sender:    sender,
			CacheFile: config.AbuseReportCacheFile(),
			PerPage:   config.AbuseReportPerPage(),
			MaxPages:  config.AbuseReportMaxPages(),
		}
		sched.ScheduleDaily(ctx, config.AbuseReportScanHour(), config.AbuseReportScanMinute(), func() {
			log.Printf("开始每日 Cloudflare 滥用报告扫描任务")
			if err := abuseReportService.RunDaily(ctx); err != nil {
				log.Printf("每日 Cloudflare 滥用报告扫描任务失败: %v", err)
			}
		})
	}

	<-ctx.Done()
}
