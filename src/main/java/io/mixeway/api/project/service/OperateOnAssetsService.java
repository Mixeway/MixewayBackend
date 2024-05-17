package io.mixeway.api.project.service;

import com.fasterxml.jackson.databind.JsonNode;
import io.mixeway.api.project.controller.OperateOnAssets;
import io.mixeway.api.project.model.AssetPutModel;
import io.mixeway.api.project.model.EditCodeProjectModel;
import io.mixeway.api.project.model.EditProjectAssetModel;
import io.mixeway.api.project.model.ProjectAssetModel;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.domain.service.intf.FindInterfaceService;
import io.mixeway.domain.service.intf.UpdateInterfaceService;
import io.mixeway.domain.service.routingdomain.FindRoutingDomainService;
import io.mixeway.domain.service.scan.CreateScanService;
import io.mixeway.domain.service.scan.FindScanService;
import io.mixeway.domain.service.scanmanager.code.CreateOrGetCodeProjectService;
import io.mixeway.domain.service.scanmanager.code.FindCodeProjectService;
import io.mixeway.domain.service.scanmanager.code.UpdateCodeProjectService;
import io.mixeway.domain.service.scanmanager.webapp.FindWebAppService;
import io.mixeway.domain.service.scanmanager.webapp.GetOrCreateWebAppService;
import io.mixeway.domain.service.scanmanager.webapp.UpdateWebAppService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.utils.PermissionFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Log4j2
public class OperateOnAssetsService {

    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    private final GetOrCreateWebAppService getOrCreateWebAppService;
    private final FindRoutingDomainService findRoutingDomainService;
    private final UpdateCodeProjectService updateCodeProjectService;
    private final AssetService assetService;
    private final FindCodeProjectService findCodeProjectService;
    private final FindWebAppService findWebAppService;
    private final FindInterfaceService findInterfaceService;
    private final PermissionFactory permissionFactory;
    private final UpdateWebAppService updateWebAppService;
    private final UpdateInterfaceService updateInterfaceService;
    private final VulnTemplate vulnTemplate;
    private final FindScanService findScanService;
    private final CreateScanService createScanService;

    public CodeProject createCodeProject(JsonNode rootNode, Project project, Principal principal) {
        String repositoryType = rootNode.path("repositoryType").asText();
        if (repositoryType.equals("single")) {
            return createSingleCodeProject(rootNode, project, principal);
        } else if (repositoryType.equals("multiple")) {
            return createMultipleCodeProject(rootNode, project, principal);
        }
        return null; // Handle invalid repositoryType
    }

    private CodeProject createSingleCodeProject(JsonNode rootNode, Project project, Principal principal) {
        log.info("[OperateOnAsset] {} Created CodeProject with name {} url {}",
                principal.getName(),
                rootNode.path("name").asText(),
                rootNode.path("repositoryUrl").asText());
        return createOrGetCodeProjectService.createCodeProject(
                rootNode.path("repositoryUrl").asText(),
                rootNode.path("name").asText(),
                rootNode.path("defaultBranch").asText(),
                principal,
                project);
    }

    private CodeProject createMultipleCodeProject(JsonNode rootNode, Project project, Principal principal) {
        CodeProject parent = createOrGetCodeProjectService.createCodeProject(
                rootNode.path("repositoryUrl").asText(),
                rootNode.path("name").asText(),
                rootNode.path("defaultBranch").asText(),
                principal,
                project);
        parent = updateCodeProjectService.setAsParent(parent);
        log.info("[OperateOnAsset] {} Created CodeProject with name {} url {}",
                principal.getName(),
                rootNode.path("name").asText(),
                rootNode.path("repositoryUrl").asText());

        JsonNode apps = rootNode.path("apps");
        for (int i = 0; i < apps.size(); i++) {
            JsonNode app = apps.get(i);
            log.info("[OperateOnAsset] {} Created Embeded CodeProject with name {} url {} and directory within repo {}",
                    principal.getName(),
                    app.path("appName").asText(),
                    rootNode.path("repositoryUrl").asText(),
                    app.path("appDirectory").asText());

            createOrGetCodeProjectService.createChildCodeProject(
                    rootNode.path("repositoryUrl").asText(),
                    app.path("appName").asText(),
                    rootNode.path("defaultBranch").asText(),
                    principal,
                    project,
                    parent,
                    app.path("appDirectory").asText());
        }
        return null;
    }

    public WebApp createWebApp(JsonNode rootNode, Project project) {
        Optional<RoutingDomain> routingDomainOptional = findRoutingDomainService.findById(Long.parseLong(rootNode.path("routingDomain").asText()));
        if (routingDomainOptional.isPresent()) {
            return getOrCreateWebAppService.createWebApp(
                    project,
                    rootNode.path("appUrl").asText(),
                    rootNode.path("appName").asText(),
                    routingDomainOptional.get(),
                    rootNode.path("headerName").asText(),
                    rootNode.path("apiKeyName").asText(),
                    rootNode.path("basicAuth").asText());
        } else {
            return null;
        }
    }

    public Interface createInterface(JsonNode rootNode, Project project, Principal principal) {
        Optional<RoutingDomain> routingDomainOptional = findRoutingDomainService.findById(Long.parseLong(rootNode.path("routingDomain").asText()));
        if (routingDomainOptional.isPresent()) {
            AssetPutModel assetPutModel = new AssetPutModel();
            assetPutModel.setAssetName(rootNode.path("name").asText());
            assetPutModel.setIpAddresses(rootNode.path("ip").asText());
            assetPutModel.setRoutingDomainForAsset(Long.parseLong(rootNode.path("routingDomain").asText()));
            assetService.saveAsset(project.getId(), assetPutModel, principal);
            return null;
        } else {
            return null;
        }
    }

    public List<ProjectAssetModel> getAssetsForProject(Project project) {
        List<ProjectAssetModel> projectAssetModels = new ArrayList<>();

        findCodeProjectService.findByProject(project).forEach(cp -> {
            List<ProjectVulnerability> codeVulns = vulnTemplate.projectVulnerabilityRepository.findByCodeProject(cp);
            long crit = codeVulns.stream()
                    .filter(cv -> cv.getSeverity().equals(Constants.VULN_CRITICALITY_CRITICAL) ||
                            cv.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH))
                    .count();
            long medium = codeVulns.stream()
                    .filter(cv -> cv.getSeverity().equals(Constants.VULN_CRITICALITY_MEDIUM))
                    .count();
            long low = codeVulns.stream()
                    .filter(cv -> cv.getSeverity().equals(Constants.VULN_CRITICALITY_LOW))
                    .count();
            projectAssetModels.add(new ProjectAssetModel().convertCodeProject(cp, (int) crit, (int) medium, (int) low));
        });

        findWebAppService.findByProject(project).forEach(wa -> {
            List<ProjectVulnerability> waVulns = vulnTemplate.projectVulnerabilityRepository.findByWebApp(wa);
            long crit = waVulns.stream()
                    .filter(cv -> cv.getSeverity().equals(Constants.VULN_CRITICALITY_CRITICAL) ||
                            cv.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH))
                    .count();
            long medium = waVulns.stream()
                    .filter(cv -> cv.getSeverity().equals(Constants.VULN_CRITICALITY_MEDIUM))
                    .count();
            long low = waVulns.stream()
                    .filter(cv -> cv.getSeverity().equals(Constants.VULN_CRITICALITY_LOW))
                    .count();
            projectAssetModels.add(new ProjectAssetModel().convertWebApp(wa, (int) crit, (int) medium, (int) low, false));
        });

        findInterfaceService.findByAssetIn(new ArrayList<>(project.getAssets())).forEach(intf -> {
            List<ProjectVulnerability> iVulns = vulnTemplate.projectVulnerabilityRepository.findByAnInterface(intf);
            long crit = iVulns.stream()
                    .filter(cv -> cv.getSeverity().equals(Constants.VULN_CRITICALITY_CRITICAL) ||
                            cv.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH))
                    .count();
            long medium = iVulns.stream()
                    .filter(cv -> cv.getSeverity().equals(Constants.VULN_CRITICALITY_MEDIUM))
                    .count();
            long low = iVulns.stream()
                    .filter(cv -> cv.getSeverity().equals(Constants.VULN_CRITICALITY_LOW))
                    .count();
            projectAssetModels.add(new ProjectAssetModel().convertInterface(intf, (int) crit, (int) medium, (int) low, false));
        });
        return projectAssetModels;
    }

    public ResponseEntity<?> editCodeProject(EditProjectAssetModel editProjectAssetModel, Optional<CodeProject> codeProject, Principal principal) {
        if (codeProject.isPresent()) {
            if (permissionFactory.canUserAccessProject(principal, codeProject.get().getProject())) {
                updateCodeProjectService.updateCodeProject(editProjectAssetModel, codeProject.get());
                log.info("[OperateOnAsset] Editing CodeProject setting name {}, repoUrl {} and branch {}",
                        editProjectAssetModel.getName(),
                        editProjectAssetModel.getTarget(),
                        editProjectAssetModel.getBranch());
                return new ResponseEntity<>(HttpStatus.OK);
            }
        }
        return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
    }

    public ResponseEntity<?> editWebApp(EditProjectAssetModel editProjectAssetModel, Optional<WebApp> webApp, Principal principal) {
        if (webApp.isPresent()) {
            if (permissionFactory.canUserAccessProject(principal, webApp.get().getProject())) {
                updateWebAppService.edit(editProjectAssetModel, webApp.get());
                log.info("[OperateOnAsset] Editing WebApp setting name {} and Url {}",
                        editProjectAssetModel.getName(),
                        editProjectAssetModel.getTarget());
                return new ResponseEntity<>(HttpStatus.OK);
            }
        }
        return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
    }

    public ResponseEntity<?> editInterface(EditProjectAssetModel editProjectAssetModel, Optional<Interface> anInterface, Principal principal) {
        if (anInterface.isPresent()) {
            if (permissionFactory.canUserAccessProject(principal, anInterface.get().getAsset().getProject())) {
                updateInterfaceService.edit(editProjectAssetModel, anInterface.get());
                log.info("[OperateOnAsset] Editing Interface setting name {} and IP {}",
                        editProjectAssetModel.getName(),
                        editProjectAssetModel.getTarget());
                return new ResponseEntity<>(HttpStatus.OK);
            }
        }
        return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
    }

    public ResponseEntity<?> getScans(Long id, String type, Principal principal) {

        List<Scan> scans = new ArrayList<>();
        switch (type) {
            case "codeProject":
                Optional<CodeProject> codeProject = findCodeProjectService.findById(id);
                if (codeProject.isPresent()) {
                    scans = findScanService.getScansForAsset(codeProject.get());
                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
                break;
            case "webApp":
                Optional<WebApp> webApp = findWebAppService.findById(id);
                if (webApp.isPresent()) {
                    scans = findScanService.getScansForAsset(webApp.get());
                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
                break;
            case "interface":
                Optional<Interface> anInterface = findInterfaceService.findById(id);
                if (anInterface.isPresent()) {
                    scans = findScanService.getScansForAsset(anInterface.get());
                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
                break;
            default:
                return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(scans, HttpStatus.OK);
    }
}