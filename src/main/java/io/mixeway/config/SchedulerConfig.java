package io.mixeway.config;

import io.mixeway.db.entity.Settings;
import io.mixeway.db.repository.SettingsRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Optional;

@Configuration
public class SchedulerConfig {
    private final SettingsRepository settingsRepository;

    SchedulerConfig(SettingsRepository settingsRepository){
        this.settingsRepository = settingsRepository;
    }

    @Bean
    public String getNetworkCronExpresion() throws Exception {
        Optional<Settings> settings = settingsRepository.findAll().stream().findFirst();
        if (settings.isPresent()){
            return settings.get().getInfraAutoCron();
        } else {
            throw new Exception("Unable to load settings");
        }
    }
    @Bean
    public String getWebAppCronExpresion() throws Exception {
        Optional<Settings> settings = settingsRepository.findAll().stream().findFirst();
        if (settings.isPresent()){
            return settings.get().getWebAppAutoCron();
        } else {
            throw new Exception("Unable to load settings");
        }
    }
    @Bean
    public String getCodeCronExpression() throws Exception {
        Optional<Settings> settings = settingsRepository.findAll().stream().findFirst();
        if (settings.isPresent()){
            return settings.get().getCodeAutoCron();
        } else {
            throw new Exception("Unable to load settings");
        }
    }
}
