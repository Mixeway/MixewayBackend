/*
 * @created  2020-08-21 : 13:03
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.rest.profile.service;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.SettingsRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.db.repository.VulnHistoryRepository;
import io.mixeway.rest.profile.model.UserProfile;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class ProfileService {
    private final UserRepository userRepository;
    private final ProjectRepository projectRepository;
    private final VulnHistoryRepository vulnHistoryRepository;
    private final SettingsRepository settingsRepository;

    public ProfileService(UserRepository userRepository, ProjectRepository projectRepository,
                          VulnHistoryRepository vulnHistoryRepository, SettingsRepository settingsRepository) {
        this.userRepository = userRepository;
        this.projectRepository = projectRepository;
        this.vulnHistoryRepository = vulnHistoryRepository;
        this.settingsRepository = settingsRepository;
    }

    /**
     * Method which return user profile. If password auth is set dummypassword is being sent back
     */
    public ResponseEntity<UserProfile> showProjects(Principal principal) {
        Optional<User> user = userRepository.findByUsernameOrCommonName(principal.getName(), principal.getName());
        if (user.isPresent()){
            int projectno = setProjectNumberForUser(user.get());
            int vulno = setVulnNumberForUser(user.get());
            Settings settings = settingsRepository.findAll().stream().findFirst().orElse(null);
            UserProfile userProfile = new UserProfile(
                    user.get().getUsername(),
                    projectno,
                    vulno,
                    StringUtils.isNotBlank(user.get().getPassword()) ? Constants.DUMMY_PASSWORD : null,
                    settings.getPasswordAuth());
            return new ResponseEntity<>(userProfile,HttpStatus.OK);
        }else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Get vulnerabilities number for users projects.
     * @param user to check
     * @return number of vulns in related projects
     */
    private int setVulnNumberForUser(User user) {
        if (user.getPermisions().equals(Constants.ROLE_USER)){
            List<VulnHistory> vulnHistoryForProjects = vulnHistoryRepository.recentHistoryForProjects(
                    user.getProjects().stream().map(Project::getId).collect(Collectors.toList())
            );
            Long vulnNumber =  vulnHistoryForProjects.stream().mapToLong(VulnHistory::getAuditVulnHistory).sum() +
                    vulnHistoryForProjects.stream().mapToLong(VulnHistory::getCodeVulnHistory).sum() +
                    vulnHistoryForProjects.stream().mapToLong(VulnHistory::getInfrastructureVulnHistory).sum() +
                    vulnHistoryForProjects.stream().mapToLong(VulnHistory::getSoftwarePacketVulnNumber).sum() +
                    vulnHistoryForProjects.stream().mapToLong(VulnHistory::getWebAppVulnHistory).sum();
            return Math.toIntExact(vulnNumber);
        } else if (user.getPermisions().equals(Constants.ROLE_ADMIN) || user.getPermisions().equals(Constants.ROLE_EDITOR_RUNNER)){
            List<VulnHistory> vulnHistoryForProjects = vulnHistoryRepository.recentHistoryForAllProjects();
            Long vulnNumber =  vulnHistoryForProjects.stream().mapToLong(VulnHistory::getAuditVulnHistory).sum() +
                    vulnHistoryForProjects.stream().mapToLong(VulnHistory::getCodeVulnHistory).sum() +
                    vulnHistoryForProjects.stream().mapToLong(VulnHistory::getInfrastructureVulnHistory).sum() +
                    vulnHistoryForProjects.stream().mapToLong(VulnHistory::getSoftwarePacketVulnNumber).sum() +
                    vulnHistoryForProjects.stream().mapToLong(VulnHistory::getWebAppVulnHistory).sum();
            return Math.toIntExact(vulnNumber);
        } else
            return 0;
    }

    /**
     * Get project number for user. If user Role is ROLE_USER it gets only private projects. Otherwise all projects are considered.
     * @param user to check
     * @return number of projects
     */
    private int setProjectNumberForUser(User user) {
        if (user.getPermisions().equals(Constants.ROLE_USER)){
            return user.getProjects().size();
        } else if (user.getPermisions().equals(Constants.ROLE_ADMIN) || user.getPermisions().equals(Constants.ROLE_EDITOR_RUNNER)){
            return projectRepository.findAll().size();
        } else
            return 0;
    }

    /**
     * Possibility to change password (if password auth is enabled)
     *
     * @param principal user
     * @return status
     */
    public ResponseEntity<Status> editProfile(Principal principal) {
        return null;
    }

    /**
     * Generation of new CICD ApiKey, previous one is deleted
     */
    public ResponseEntity<Status> regenerateCicdApiKey(Principal principal) {
        return null;
    }
}
