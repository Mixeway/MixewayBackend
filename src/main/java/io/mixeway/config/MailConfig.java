package io.mixeway.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.VaultResponseSupport;
import io.mixeway.db.entity.Settings;
import io.mixeway.db.repository.SettingsRepository;

import java.util.Map;
import java.util.Properties;

@Configuration
public class MailConfig {
    private final SettingsRepository settingsRepository;
    private final VaultOperations operations;

    @Autowired
    MailConfig(SettingsRepository settingsRepository, VaultOperations operations){
        this.settingsRepository = settingsRepository;
        this.operations = operations;
    }
    @Bean
    public JavaMailSenderImpl emailService() {
        Settings settings = settingsRepository.findAll().stream().findFirst().get();
        VaultResponseSupport<Map<String,Object>> password = operations.read("secret/"+settings.getSmtpPassword());
        Properties mailProperties = new Properties();
        if (settings.getSmtpHost() != null) {
            mailProperties.put("spring.mail.host", settings.getSmtpHost());
            mailProperties.put("spring.mail.port", settings.getSmtpPort());
            mailProperties.put("spring.mail.username", settings.getSmtpUsername());
            mailProperties.put("spring.mail.password", password.getData().get("password").toString());
            mailProperties.put("spring.mail.properties.mail.smtp.auth", settings.getSmtpAuth());
            mailProperties.put("spring.mail.properties.mail.smtp.starttls.enable", settings.getSmtpTls());
            mailProperties.put("mail.smtp.starttls.enable", settings.getSmtpTls());
            JavaMailSenderImpl javaMailSender = new JavaMailSenderImpl();
            javaMailSender.setJavaMailProperties(mailProperties);
            javaMailSender.setHost(settings.getSmtpHost());
            javaMailSender.setPort(settings.getSmtpPort());
            javaMailSender.setUsername(settings.getSmtpUsername());
            javaMailSender.setPassword(password.getData().get("password").toString());
            return javaMailSender;
        }
        return new JavaMailSenderImpl();
    }
}
