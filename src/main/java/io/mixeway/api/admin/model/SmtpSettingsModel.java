package io.mixeway.api.admin.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SmtpSettingsModel {
    Boolean smtpAuth;
    Boolean smtpTls;
    String smtpHost;
    int smtpPort;
    String smtpUsername;
    String smtpPassword;
    String domain;
}
