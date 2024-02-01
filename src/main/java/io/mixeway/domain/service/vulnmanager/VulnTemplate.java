package io.mixeway.domain.service.vulnmanager;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.scanmanager.service.bugtracking.BugTracking;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.net.URISyntaxException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * @author gsiewruk
 */
@Component
public class VulnTemplate {
    public final CreateOrGetVulnerabilityService createOrGetVulnerabilityService;
    public final ProjectVulnerabilityRepository projectVulnerabilityRepository;
    public final VulnerabilitySourceRepository vulnerabilitySourceRepository;
    public final VulnerabilityRepository vulnerabilityRepository;
    public final StatusRepository statusRepository;
    public final CisRequirementRepository cisRequirementRepository;
    private final List<BugTracking> bugTrackings;
    private final BugTrackerRepository bugTrackerRepository;
    public final Status STATUS_NEW;
    public final Status STATUS_EXISTING;
    public final Status STATUS_REMOVED;
    public final VulnerabilitySource SOURCE_NETWORK;
    public final VulnerabilitySource SOURCE_SOURCECODE;
    public final VulnerabilitySource SOURCE_WEBAPP;
    public final VulnerabilitySource SOURCE_OPENSOURCE;
    public final VulnerabilitySource SOURCE_OSPACKAGE;
    public final VulnerabilitySource SOURCE_GITLEAKS;
    public final VulnerabilitySource SOURCE_IAC;
    public final VulnerabilitySource SOURCE_CISBENCHMARK;
    private static final Logger log = LoggerFactory.getLogger(VulnTemplate.class);


    public VulnTemplate(CreateOrGetVulnerabilityService createOrGetVulnerabilityService, ProjectVulnerabilityRepository projectVulnerabilityRepository,
                        VulnerabilitySourceRepository vulnerabilitySourceRepository, StatusRepository statusRepository,
                        VulnerabilityRepository vulnerabilityRepository, CisRequirementRepository cisRequirementRepository,
                        List<BugTracking> bugTrackings, BugTrackerRepository bugTrackerRepository){
        this.bugTrackerRepository = bugTrackerRepository;
        this.bugTrackings = bugTrackings;
        this.statusRepository = statusRepository;
        this.vulnerabilitySourceRepository = vulnerabilitySourceRepository;
        this.createOrGetVulnerabilityService = createOrGetVulnerabilityService;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.projectVulnerabilityRepository = projectVulnerabilityRepository;
        this.cisRequirementRepository = cisRequirementRepository;
        STATUS_EXISTING = statusRepository.findByName(Constants.STATUS_EXISTING);
        STATUS_NEW = statusRepository.findByName(Constants.STATUS_NEW);
        STATUS_REMOVED = statusRepository.findByName(Constants.STATUS_REMOVED);
        SOURCE_NETWORK = vulnerabilitySourceRepository.findByName(Constants.VULN_TYPE_NETWORK);
        SOURCE_SOURCECODE = vulnerabilitySourceRepository.findByName(Constants.VULN_TYPE_SOURCECODE);
        SOURCE_WEBAPP = vulnerabilitySourceRepository.findByName(Constants.VULN_TYPE_WEBAPP);
        SOURCE_OPENSOURCE = vulnerabilitySourceRepository.findByName(Constants.VULN_TYPE_OPENSOURCE);
        SOURCE_OSPACKAGE = vulnerabilitySourceRepository.findByName(Constants.VULN_TYPE_OSPACKAGE);
        SOURCE_GITLEAKS = vulnerabilitySourceRepository.findByName(Constants.VULNEARBILITY_SOURCE_GITLEAKS);
        SOURCE_CISBENCHMARK = vulnerabilitySourceRepository.findByName(Constants.VULNEARBILITY_SOURCE_CISBENCHMARK);
        SOURCE_IAC = vulnerabilitySourceRepository.findByName(Constants.VULNEARBILITY_SOURCE_IAC);
    }

    public void vulnerabilityPersist(List<ProjectVulnerability> oldTmpVulns, ProjectVulnerability projectVulnerability){
        projectVulnerability.setSeverity(projectVulnerability.getCustomSeverity());
        List<ProjectVulnerability> oldVulnsToKeep = oldTmpVulns.stream()
                .filter(o -> o.equals(projectVulnerability))
                .collect(Collectors.toList());
        if (oldVulnsToKeep.size() >0 ){
            oldVulnsToKeep.forEach(o -> o.setStatus(STATUS_EXISTING));
            projectVulnerabilityRepository.saveAll(oldVulnsToKeep);
        } else {
            projectVulnerability.setStatus(STATUS_NEW);
            projectVulnerability.setGrade(-1);
            projectVulnerabilityRepository.save(projectVulnerability);
        }
    }

    public void vulnerabilityPersistList(List<ProjectVulnerability> oldTmpVulns, List<ProjectVulnerability> projectVulnerabilities) {
        projectVulnerabilities.forEach(vuln -> vuln.setSeverity(vuln.getCustomSeverity()));
        List<ProjectVulnerability> newVulns = new ArrayList<>();
        for (ProjectVulnerability projectVulnerability : projectVulnerabilities){
            List<ProjectVulnerability> oldVulnsToKeep = oldTmpVulns.stream()
                    .filter(o -> o.equals(projectVulnerability))
                    .collect(Collectors.toList());
            if (oldVulnsToKeep.size() >0 ){
                oldVulnsToKeep.forEach(o -> o.setStatus(STATUS_EXISTING));
                oldVulnsToKeep.forEach(projectVulnerabilityRepository::saveAndFlush);
            } else {
                projectVulnerability.setStatus(STATUS_NEW);
                projectVulnerability.setGrade(-1);
                newVulns.add(projectVulnerability);
            }
        }
        
        projectVulnerabilityRepository.saveAll(newVulns.stream().distinct().collect(Collectors.toList()));
    }

    public void vulnerabilityPersistListSoftware(List<ProjectVulnerability> oldTmpVulns, List<ProjectVulnerability> projectVulnerabilities) {
        projectVulnerabilities.forEach(vuln -> vuln.setSeverity(vuln.getCustomSeverity()));
        List<ProjectVulnerability> newVulns = new ArrayList<>();
        for (ProjectVulnerability projectVulnerability : projectVulnerabilities
                .stream()
                .filter(distinctByKeys(ProjectVulnerability::getCodeProject, ProjectVulnerability::getSoftwarePacket, ProjectVulnerability::getVulnerability, ProjectVulnerability::getSeverity, ProjectVulnerability::getCodeProjectBranch))
                .collect(Collectors.toList())){
            List<ProjectVulnerability> oldVulnsToKeep = oldTmpVulns.stream()
                    .filter(o -> o.equals(projectVulnerability))
                    .collect(Collectors.toList());
            if (oldVulnsToKeep.size() >0 ){
                oldVulnsToKeep.forEach(o -> o.setStatus(STATUS_EXISTING));
                oldVulnsToKeep.forEach(projectVulnerabilityRepository::saveAndFlush);

            } else {
                projectVulnerability.setStatus(STATUS_NEW);
                projectVulnerability.setGrade(-1);
                newVulns.add(projectVulnerability);
            }
        }
        projectVulnerabilityRepository.saveAll(newVulns);
    }

    public void processBugTracking(CodeProject codeProject, VulnerabilitySource vulnerabilitySource) throws URISyntaxException {

        Optional<BugTracker> bugTracker = bugTrackerRepository.findByProjectAndVulns(codeProject.getProject(), vulnerabilitySource.getName());
        if (SOURCE_OPENSOURCE.equals(vulnerabilitySource)) {
            List<ProjectVulnerability> projectVulnerabilities = projectVulnerabilityRepository
                    .findByCodeProjectAndVulnerabilitySourceAndTicketIdIsNullAndSeverityIn(codeProject, vulnerabilitySource, Collections.singletonList("Critical"));
            processOpenSourceIssues(projectVulnerabilities, bugTracker, codeProject);
        } else if (SOURCE_SOURCECODE.equals(vulnerabilitySource)) {
            List<ProjectVulnerability> projectVulnerabilities = projectVulnerabilityRepository
                    .findByCodeProjectAndVulnerabilitySourceAndTicketIdIsNullAndSeverityIn(codeProject, vulnerabilitySource, Collections.singletonList("High"));
            processSourceCodeIssues(projectVulnerabilities, bugTracker, codeProject);
        } else {
            log.warn("[BugTracker] Unsupported Vulnerability type {}. Check newest version of Mixeway on GitHub.", vulnerabilitySource.getName());
        }
       
    }

    private void processSourceCodeIssues(List<ProjectVulnerability> projectVulnerabilities, Optional<BugTracker> bugTracker, CodeProject codeProject) throws URISyntaxException {
        List<Vulnerability> distinctVulnsNamesForCode = projectVulnerabilities.stream().map(ProjectVulnerability::getVulnerability).distinct().collect(Collectors.toList());
        projectVulnerabilities = projectVulnerabilities.stream().filter(pv -> !pv.getAnalysis().equals(Constants.FORTIFY_NOT_AN_ISSUE)).collect(Collectors.toList());
        log.info("[SourceCodeScan] Proceeding with SourceCode Issuing tickets. {} Ticket to be issued.", distinctVulnsNamesForCode.size());
        for (Vulnerability v : distinctVulnsNamesForCode){
            List<ProjectVulnerability> vulnsToIssue = projectVulnerabilities.stream().filter(pv -> pv.getVulnerability().equals(v)).collect(Collectors.toList());
            if (projectVulnerabilities.size() > 0 && bugTracker.isPresent()) {
                for (BugTracking bugTracking : bugTrackings) {
                    if (bugTracking.canProcessRequest(bugTracker.get())) {
                        bugTracking.processRequestMultiVuln(projectVulnerabilityRepository, vulnsToIssue,bugTracker.get(), codeProject.getProject(),"SourceCode","Autoaction",false);
                    }
                }
            }
        }
    }

    private void processOpenSourceIssues(List<ProjectVulnerability> projectVulnerabilities, Optional<BugTracker> bugTracker, CodeProject codeProject) throws URISyntaxException {
        List<String> libsWithVulns = projectVulnerabilities.stream().map(ProjectVulnerability::getLocation).distinct().collect(Collectors.toList());
        if (libsWithVulns.size() > 0 )
            log.info("[OpenSourceScan] Proceeding with OpenSource Issuing tickets. {} Ticket to be issued.", libsWithVulns.size());
        for (String lib : libsWithVulns) {
            List<ProjectVulnerability> vulnsToIssue = projectVulnerabilities.stream().filter(pv -> pv.getLocation().equals(lib)).collect(Collectors.toList());
            if (projectVulnerabilities.size() > 0 && bugTracker.isPresent()) {
                for (BugTracking bugTracking : bugTrackings) {
                    if (bugTracking.canProcessRequest(bugTracker.get())) {
                        bugTracking.processRequestMultiVuln(projectVulnerabilityRepository, vulnsToIssue,bugTracker.get(), codeProject.getProject(),"OpenSource","Autoaction",false);
                    }
                }
            }
        }
    }

    @SafeVarargs
    private static <T> Predicate<T> distinctByKeys(Function<? super T, ?>... keyExtractors)
    {
        final Map<List<?>, Boolean> seen = new ConcurrentHashMap<>();

        return t ->
        {
            final List<?> keys = Arrays.stream(keyExtractors)
                    .map(ke -> ke.apply(t))
                    .collect(Collectors.toList());

            return seen.putIfAbsent(keys, Boolean.TRUE) == null;
        };
    }
}
