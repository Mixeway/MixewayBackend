package io.mixeway.domain.service.settings;

import io.mixeway.api.admin.model.AuthSettingsModel;
import io.mixeway.api.admin.model.CronSettings;
import io.mixeway.api.admin.model.SmtpSettingsModel;
import io.mixeway.api.admin.model.VulnAuditorEditSettings;
import io.mixeway.db.entity.Settings;
import io.mixeway.db.repository.SettingsRepository;
import io.mixeway.utils.VaultHelper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class UpdateSettingsService {
    private final SettingsRepository settingsRepository;
    private final VaultHelper vaultHelper;

    public void updateSmtp(SmtpSettingsModel smtpSettingsModel, String name, Settings settings){
        if (smtpSettingsModel.getSmtpAuth() && smtpSettingsModel.getSmtpPassword()!=null && smtpSettingsModel.getSmtpUsername()!=null){
            settings.setSmtpAuth(smtpSettingsModel.getSmtpAuth());
            settings.setSmtpUsername(smtpSettingsModel.getSmtpUsername());
            settings.setDomain(smtpSettingsModel.getDomain());
            String uuidToken = UUID.randomUUID().toString();
            if (vaultHelper.savePassword(smtpSettingsModel.getSmtpPassword(),uuidToken)) {
                settings.setSmtpPassword(uuidToken);
            } else {
                settings.setSmtpPassword(smtpSettingsModel.getSmtpPassword());
            }
        }
        settings.setSmtpHost(smtpSettingsModel.getSmtpHost());
        settings.setSmtpPort(smtpSettingsModel.getSmtpPort());
        settings.setSmtpTls(smtpSettingsModel.getSmtpTls());
        settingsRepository.save(settings);
    }
    public void updateAuth(Settings settings, AuthSettingsModel authSettingsModel){
        settings.setPasswordAuth(authSettingsModel.getPasswordAuth());
        settings.setCertificateAuth(authSettingsModel.getCertificateAuth());
        settingsRepository.save(settings);
    }

    public void updateMasterApiKey(Settings settings) {
        settings.setMasterApiKey(UUID.randomUUID().toString());
        settingsRepository.save(settings);
    }
    public void deleteMasterApiKey(Settings settings) {
        settings.setMasterApiKey(null);
        settingsRepository.save(settings);
    }

    public void updateInfraCron(Settings settings, CronSettings cronSettings) {
        settings.setInfraAutoCron(cronSettings.getExpression());
        settingsRepository.save(settings);
    }

    public void updateWebAppCron(Settings settings, CronSettings cronSettings) {
        settings.setWebAppAutoCron(cronSettings.getExpression());
        settingsRepository.save(settings);
    }

    public void updateCodeCron(Settings settings, CronSettings cronSettings) {
        settings.setCodeAutoCron(cronSettings.getExpression());
        settingsRepository.save(settings);
    }

    public void updateTrendCron(Settings settings, CronSettings cronSettings) {
        settings.setTrendEmailCron(cronSettings.getExpression());
        settingsRepository.save(settings);
    }

    public void updateVulnAuditorSettings(Settings settings, VulnAuditorEditSettings vulnAuditorEditSettings){
        settings.setVulnAuditorEnable(vulnAuditorEditSettings.isEnabled());
        settings.setVulnAuditorUrl(vulnAuditorEditSettings.getUrl());
        settingsRepository.save(settings);
    }

    public void initialize(Settings settings) {
        settings.setInitialized(true);
        settingsRepository.save(settings);
    }
}
