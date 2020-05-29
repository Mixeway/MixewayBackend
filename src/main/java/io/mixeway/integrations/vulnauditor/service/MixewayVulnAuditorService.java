package io.mixeway.integrations.vulnauditor.service;

import io.mixeway.db.entity.Settings;
import io.mixeway.db.repository.SettingsRepository;
import io.mixeway.domain.service.vulnerability.VulnTemplate;
import io.mixeway.integrations.vulnauditor.apiclient.MixewayVulnAuditorApiClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
public class MixewayVulnAuditorService {
    private final static Logger log = LoggerFactory.getLogger(MixewayVulnAuditorService.class);
    private final VulnTemplate vulnTemplate;
    private final MixewayVulnAuditorApiClient mixewayVulnAuditorApiClient;
    private final SettingsRepository settingsRepository;

    public MixewayVulnAuditorService(VulnTemplate vulnTemplate, MixewayVulnAuditorApiClient mixewayVulnAuditorApiClient,
                                     SettingsRepository settingsRepository){
        this.vulnTemplate = vulnTemplate;
        this.mixewayVulnAuditorApiClient = mixewayVulnAuditorApiClient;
        this.settingsRepository = settingsRepository;
    }

    public void perdictVulnerabilities() throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        Optional<Settings> settings = settingsRepository.findAll().stream().findFirst();
        if (settings.isPresent() && settings.get().isVulnAuditorEnable()){
            mixewayVulnAuditorApiClient.perdict(vulnTemplate.projectVulnerabilityRepository.findByGrade(-1), settings.get().getVulnAuditorUrl());
        }
    }
}
