package io.mixeway.scanmanager.integrations.vulnauditor.service;

import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.db.entity.Settings;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.SettingsRepository;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.integrations.vulnauditor.apiclient.MixewayVulnAuditorApiClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Optional;

/**
 * @author gsiewruk
 */
@Service
public class MixewayVulnAuditorService {
    private final static Logger log = LoggerFactory.getLogger(MixewayVulnAuditorService.class);
    private final VulnTemplate vulnTemplate;
    private final ProjectRepository projectRepository;
    private final MixewayVulnAuditorApiClient mixewayVulnAuditorApiClient;
    private final SettingsRepository settingsRepository;

    public MixewayVulnAuditorService(VulnTemplate vulnTemplate, MixewayVulnAuditorApiClient mixewayVulnAuditorApiClient,
                                     SettingsRepository settingsRepository, ProjectRepository projectRepository){
        this.vulnTemplate = vulnTemplate;
        this.projectRepository = projectRepository;
        this.mixewayVulnAuditorApiClient = mixewayVulnAuditorApiClient;
        this.settingsRepository = settingsRepository;
    }

    @Transactional(isolation = Isolation.READ_COMMITTED)
    public void perdictVulnerabilities() throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        Optional<Settings> settings = settingsRepository.findAll().stream().findFirst();
        if (settings.isPresent() && settings.get().isVulnAuditorEnable()) {
            for (Project project : projectRepository.findByVulnAuditorEnable(true)) {
                List<ProjectVulnerability> projectVulnerabilities = vulnTemplate.projectVulnerabilityRepository.findByGradeAndProject(-1, project);
                if (settings.isPresent() && settings.get().isVulnAuditorEnable() && projectVulnerabilities.size() > 0) {
                    mixewayVulnAuditorApiClient.perdict(projectVulnerabilities, settings.get().getVulnAuditorUrl());
                }

            }
        }
    }
}
