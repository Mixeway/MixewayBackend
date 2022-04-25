/*
 * @created  2021-05-21 : 16:42
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.scanmanager.service.bugtracking;

import io.mixeway.db.entity.BugTracker;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.db.repository.BugTrackerRepository;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;

@Service
public class BugTrackingService {
    private static final Logger log = LoggerFactory.getLogger(BugTrackingService.class);
    private static List<BugTracking> bugTrackingList;
    private static VulnTemplate vulnTemplate;
    private static BugTrackerRepository bugTrackerRepository;


    public BugTrackingService(List<BugTracking> bugTrackings, VulnTemplate vulnTemplate, BugTrackerRepository bugTrackerRepository){
        BugTrackingService.bugTrackingList = bugTrackings;
        BugTrackingService.vulnTemplate = vulnTemplate;
        BugTrackingService.bugTrackerRepository = bugTrackerRepository;
    }

    static public void deleteTicket(ProjectVulnerability projectVulnerability) throws URISyntaxException {

        if (StringUtils.isNotBlank(projectVulnerability.getTicketId())) {

            Optional<BugTracker> bugTracker = bugTrackerRepository.findByProjectAndVulns(projectVulnerability.getProject(), projectVulnerability.getVulnerabilitySource().getName());
            Long vulnWithSameTicketId = vulnTemplate.projectVulnerabilityRepository.countByProjectAndTicketId(projectVulnerability.getProject(), projectVulnerability.getTicketId());
            if (vulnWithSameTicketId == 1 && bugTracker.isPresent()){
                for(BugTracking bugTracking : bugTrackingList){
                    if (bugTracking.canProcessRequest(bugTracker.get())){
                        bugTracking.closeIssue(projectVulnerability.getTicketId(),bugTracker.get());
                        log.info("[BugTracker] Delating Issue {} due to vulnerability removal", projectVulnerability.getTicketId());
                    }
                }
            }

        }

    }
}
