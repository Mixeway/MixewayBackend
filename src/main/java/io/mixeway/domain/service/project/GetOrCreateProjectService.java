package io.mixeway.domain.service.project;

import io.mixeway.api.protocol.cioperations.GetInfoRequest;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.Project;
import io.mixeway.scanmanager.model.NetworkScanRequestModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.parameters.P;
import org.springframework.stereotype.Service;

import javax.swing.text.html.Option;
import java.security.Principal;
import java.util.Optional;

@Service
public class GetOrCreateProjectService {

    private final FindProjectService findProjectService;
    private final CreateProjectService createProjectService;


    @Autowired
    public GetOrCreateProjectService(FindProjectService findProjectService, CreateProjectService createProjectService) {
        this.findProjectService = findProjectService;
        this.createProjectService = createProjectService;
    }

    public Project getProjectId(String ciid, String projectName, Principal principal) {
        Optional<Project> findProject = findProjectService.findProjectByCiid(ciid);
        return findProject.orElseGet(() -> createProjectService.createAndReturnProject(projectName, ciid, principal));
    }

    public Project getProject(NetworkScanRequestModel req, Principal principal) {
        Optional<Project> findProject = findProjectService.findProjectByCiid(req.getCiid());
        return findProject.orElseGet(() -> createProjectService.createAndReturnProject(req.getProjectName(), req.getCiid(), principal));
    }
    public Project getProject(GetInfoRequest req, Principal principal) {
        return null;
    }

    public Project getProjectByName(String name, Principal principal) {
        Optional<Project> findProject = findProjectService.findProjectByName(name);
        return findProject.orElseGet(() -> createProjectService.createAndReturnProject(name, Constants.CIID_NONE,principal));
    }
}
