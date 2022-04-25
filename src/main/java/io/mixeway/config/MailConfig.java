package io.mixeway.config;

import io.mixeway.utils.VaultHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import io.mixeway.db.entity.Settings;
import io.mixeway.db.repository.SettingsRepository;

import java.util.Properties;

@Configuration
public class MailConfig {
    private final SettingsRepository settingsRepository;
    private final VaultHelper vaultHelper;

    @Autowired
    MailConfig(SettingsRepository settingsRepository, VaultHelper vaultHelper){
        this.settingsRepository = settingsRepository;
        this.vaultHelper = vaultHelper;
    }
    @Bean
    public JavaMailSenderImpl emailService() {
        Settings settings = settingsRepository.findAll().stream().findFirst().orElse(null);
        Properties mailProperties = new Properties();
        assert settings != null;
        if (settings.getSmtpHost() != null) {
            mailProperties.put("spring.mail.host", settings.getSmtpHost());
            mailProperties.put("spring.mail.port", settings.getSmtpPort());
            mailProperties.put("spring.mail.username", settings.getSmtpUsername());
            mailProperties.put("spring.mail.password", vaultHelper.getPassword(settings.getSmtpPassword()));
            mailProperties.put("spring.mail.properties.mail.smtp.auth", settings.getSmtpAuth());
            mailProperties.put("spring.mail.properties.mail.smtp.starttls.enable", settings.getSmtpTls());
            mailProperties.put("mail.smtp.starttls.enable", settings.getSmtpTls());
            JavaMailSenderImpl javaMailSender = new JavaMailSenderImpl();
            javaMailSender.setJavaMailProperties(mailProperties);
            javaMailSender.setHost(settings.getSmtpHost());
            javaMailSender.setPort(settings.getSmtpPort());
            javaMailSender.setUsername(settings.getSmtpUsername());
            javaMailSender.setPassword(vaultHelper.getPassword(settings.getSmtpPassword()));
            return javaMailSender;
        }
        return new JavaMailSenderImpl();
    }
}
