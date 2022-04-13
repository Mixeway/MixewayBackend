/*
 * @created  2020-08-21 : 13:03
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.api.profile.service;

import io.mixeway.api.profile.model.UpdateProfileModel;
import io.mixeway.api.profile.model.UserProfile;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.Settings;
import io.mixeway.db.entity.User;
import io.mixeway.db.entity.VulnHistory;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.SettingsRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.db.repository.VulnHistoryRepository;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.settings.GetSettingsService;
import io.mixeway.domain.service.user.FindUserService;
import io.mixeway.domain.service.vulnhistory.FindVulnHistoryService;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.Principal;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Log4j2
@RequiredArgsConstructor
public class ProfileService {
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final FindUserService findUserService;
    private final GetSettingsService getSettingsService;
    private final FindVulnHistoryService findVulnHistoryService;
    private final FindProjectService findProjectService;



    /**
     * Method which return user profile. If password auth is set dummypassword is being sent back
     */
    public ResponseEntity<UserProfile> showProjects(Principal principal) {
        Optional<User> user = findUserService.findByUsernameOrCommonName(principal.getName(), principal.getName());
        if (user.isPresent()){
            int projectno = setProjectNumberForUser(user.get());
            int vulno = setVulnNumberForUser(user.get());
            Settings settings = getSettingsService.getSettings();
            UserProfile userProfile = new UserProfile(
                    user.get().getUsername(),
                    projectno,
                    vulno,
                    StringUtils.isNotBlank(user.get().getPassword()) ? Constants.DUMMY_PASSWORD : null,
                    settings.getPasswordAuth(),
                    user.get().getPermisions());
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
            List<VulnHistory> vulnHistoryForProjects = findVulnHistoryService.recentHistoryForProjects(user.getProjects().stream().map(Project::getId).collect(Collectors.toList()));
            return getVulnHistory(vulnHistoryForProjects);
        } else if (user.getPermisions().equals(Constants.ROLE_ADMIN) || user.getPermisions().equals(Constants.ROLE_EDITOR_RUNNER)){
            List<VulnHistory> vulnHistoryForProjects = findVulnHistoryService.recentHistoryForAllProjects();
            return getVulnHistory(vulnHistoryForProjects);
        } else
            return 0;
    }

    private int getVulnHistory(List<VulnHistory> vulnHistoryForProjects) {
        long vulnNumber =  vulnHistoryForProjects.stream().mapToLong(VulnHistory::getAuditVulnHistory).sum() +
                vulnHistoryForProjects.stream().mapToLong(VulnHistory::getCodeVulnHistory).sum() +
                vulnHistoryForProjects.stream().mapToLong(VulnHistory::getInfrastructureVulnHistory).sum() +
                vulnHistoryForProjects.stream().mapToLong(VulnHistory::getSoftwarePacketVulnNumber).sum() +
                vulnHistoryForProjects.stream().mapToLong(VulnHistory::getWebAppVulnHistory).sum();
        return Math.toIntExact(vulnNumber);
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
            return findProjectService.findAll().size();
        } else
            return 0;
    }

    /**
     * Possibility to change password (if password auth is enabled)
     *
     *
     * @param updateProfileModel model with passwords
     * @param principal user
     * @return status
     */
    @Transactional
    public ResponseEntity<Status> editProfile(UpdateProfileModel updateProfileModel, Principal principal) {
        Optional<User> user = findUserService.findByUsernameOrCommonName(principal.getName(), principal.getName());
        Settings settings = getSettingsService.getSettings();
        if (user.isPresent() && settings.getPasswordAuth()) {
            if ((user.get().getPassword() == null && updateProfileModel.getOldPassword()== null) || bCryptPasswordEncoder.matches(updateProfileModel.getOldPassword(), user.get().getPassword())
                && updateProfileModel.getNewPassword().equals(updateProfileModel.getNewPasswordRepeat())
                && updateProfileModel.getNewPassword().length() >= 8){
                user.get().setPassword(bCryptPasswordEncoder.encode(updateProfileModel.getNewPassword()));
                log.info("Password for {} changed successfully", user.get().getUsername());
                return new ResponseEntity<>(HttpStatus.OK);
            } else {
                return new ResponseEntity<>(HttpStatus.PRECONDITION_FAILED);
            }
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Generation of new CICD ApiKey, previous one is deleted
     */
    @Transactional
    public ResponseEntity<Status> regenerateCicdApiKey(Principal principal) {
        Optional<User> user = findUserService.findByUsernameOrCommonName(principal.getName(), principal.getName());
        if (user.isPresent()) {
            user.get().setApiKey(UUID.randomUUID().toString());
            return new ResponseEntity<>(new Status("Ok", user.get().getApiKey()), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }
}
