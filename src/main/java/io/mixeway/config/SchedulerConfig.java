package io.mixeway.config;

import io.mixeway.db.entity.Settings;
import io.mixeway.db.repository.SettingsRepository;
import io.mixeway.rest.admin.service.AdminScannerRestService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Optional;

@Configuration
public class SchedulerConfig {
    private final SettingsRepository settingsRepository;
    private static final Logger log = LoggerFactory.getLogger(SchedulerConfig.class);

    SchedulerConfig(SettingsRepository settingsRepository){
        this.settingsRepository = settingsRepository;
    }

    @Bean
    public String getNetworkCronExpresion() throws Exception {
        Optional<Settings> settings = settingsRepository.findAll().stream().findFirst();
        if (settings.isPresent()){
            return settings.get().getInfraAutoCron();
        } else {
            log.warn("Cannot load Settings, setting NetworkScan Cron to default '0 55 1 * * FRI'");
            return "0 55 1 * * FRI";
        }
    }
    @Bean
    public String getWebAppCronExpresion() throws Exception {
        Optional<Settings> settings = settingsRepository.findAll().stream().findFirst();
        if (settings.isPresent()){
            return settings.get().getWebAppAutoCron();
        } else {
            log.warn("Cannot load Settings, setting WebApp Cron to default '0 55 1 * * FRI'");
            return "0 55 1 * * FRI";
        }
    }
    @Bean
    public String getCodeCronExpression() throws Exception {
        Optional<Settings> settings = settingsRepository.findAll().stream().findFirst();
        if (settings.isPresent()){
            return settings.get().getCodeAutoCron();
        } else {
            log.warn("Cannot load Settings, setting CodeScan Cron to default '0 55 1 * * FRI'");
            return "0 55 1 * * FRI";
        }
    }
    @Bean
    public String getTrendEmailExpression() throws Exception {
        Optional<Settings> settings = settingsRepository.findAll().stream().findFirst();
        if (settings.isPresent()){
            return settings.get().getTrendEmailCron();
        } else {
            log.warn("Cannot load Settings, setting Email Trend Cron to default '0 55 1 * * FRI'");
            return "0 55 1 * * FRI";
        }
    }
}
