package io.mixeway.integrations.vulnauditor.scheduler;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.domain.service.vulnerability.VulnTemplate;
import io.mixeway.integrations.infrastructurescan.plugin.remotefirewall.apiclient.RfwApiClient;
import io.mixeway.integrations.infrastructurescan.plugin.remotefirewall.model.Rule;
import io.mixeway.integrations.opensourcescan.service.OpenSourceScanService;
import io.mixeway.integrations.vulnauditor.service.MixewayVulnAuditorService;
import io.mixeway.pojo.DOPMailTemplateBuilder;
import io.mixeway.pojo.EmailVulnHelper;
import io.mixeway.pojo.ScanHelper;
import io.mixeway.rest.utils.ProjectRiskAnalyzer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import javax.mail.internet.MimeMessage;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

@Component
@Transactional
public class VulnAuditorScheduler {

    private final MixewayVulnAuditorService mixewayVulnAuditorService;
    @Autowired
    public VulnAuditorScheduler(MixewayVulnAuditorService mixewayVulnAuditorService) {
        this.mixewayVulnAuditorService = mixewayVulnAuditorService;
    }
    @Scheduled(fixedDelay = 300000)
    public void predict() throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        mixewayVulnAuditorService.perdictVulnerabilities();
    }
}
