package io.mixeway.api.project.service;

import io.mixeway.api.project.model.IaasApiPutModel;
import io.mixeway.api.project.model.IaasModel;
import io.mixeway.db.entity.IaasApi;
import io.mixeway.db.entity.IaasApiType;
import io.mixeway.db.entity.Project;
import io.mixeway.domain.service.iaasapi.DeleteIaasApiService;
import io.mixeway.domain.service.iaasapi.GetOrCreateIaasApiService;
import io.mixeway.domain.service.iaasapi.UpdateIaasApiService;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.servicediscovery.service.IaasService;
import io.mixeway.utils.PermissionFactory;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.security.Principal;
import java.util.List;
import java.util.Optional;

@Service
@Log4j2
@RequiredArgsConstructor
public class IaasApiService {
    private final PermissionFactory permissionFactory;
    private final IaasService iaasApiService;
    private final FindProjectService findProjectService;
    private final UpdateIaasApiService updateIaasApiService;
    private final DeleteIaasApiService deleteIaasApiService;
    private final GetOrCreateIaasApiService getOrCreateIaasApiService;

    public ResponseEntity<IaasModel> showIaasApi(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if ( project.isPresent() &&
                permissionFactory.canUserAccessProject(principal, project.get()) &&
                project.get().getIaasApis().size() == 1){
            Optional<IaasApi> iaasApi = project.get().getIaasApis().stream().findFirst();
            IaasModel iaasModel = new IaasModel();
            if (iaasApi.isPresent()) {
                iaasModel.setAuto(iaasApi.get().getEnabled());
                iaasModel.setEnabled(iaasApi.get().getStatus());
                iaasModel.setIam(iaasApi.get().getIamUrl());
                iaasModel.setService(iaasApi.get().getServiceUrl());
                iaasModel.setNetwork(iaasApi.get().getNetworkUrl());
                iaasModel.setProject(iaasApi.get().getTenantId());
            }
            return new ResponseEntity<>(iaasModel, HttpStatus.OK);

        } else if (project.isPresent()) {
            return new ResponseEntity<>(new IaasModel(),HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> saveIaasApi(Long id, IaasApiPutModel iaasApiPutModel, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            if (project.get().getIaasApis().size() >0){
                return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
            } else {
               iaasApiService.saveApi(iaasApiPutModel,project.get());
                log.info("{} - Saved new IaasApi for project {}", principal.getName(), project.get().getName());
                return new ResponseEntity<>(new Status("ok"), HttpStatus.CREATED);
            }
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> testIaasApi(Long id, Principal principal) {

        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            Optional<IaasApi> api = project.get().getIaasApis().stream().findFirst();
            if (api.isPresent() && api.get().getProject().getId().equals(project.get().getId())) {
                try {
                    iaasApiService.testApi(api.get());
                } catch (Exception e) {
                    log.error("Testing IAAS API of Type {} failed reason: {}", api.get().getIaasApiType().getName(), e.getLocalizedMessage());
                    return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
                }
                return new ResponseEntity<>(new Status("ok"), HttpStatus.OK);
            }
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
    }

    public ResponseEntity<Status> iaasApiEnableSynchro(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            Optional<IaasApi> api = project.get().getIaasApis().stream().findFirst();
            if (api.isPresent() && api.get().getProject().getId().equals(project.get().getId()) && api.get().getStatus()) {
                updateIaasApiService.enable(api.get());
                log.info("{} - Enabled auto synchro of IaasApi for project {}", principal.getName(), project.get().getName());
                return new ResponseEntity<>(HttpStatus.OK);
            }
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
    }

    public ResponseEntity<Status> iaasApiDisableSynchro(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            Optional<IaasApi> api = project.get().getIaasApis().stream().findFirst();
            if (api.isPresent() && api.get().getProject().getId().equals(project.get().getId())) {
                updateIaasApiService.disable(api.get());
                log.info("{} - Disabled auto synchro of IaasApi for project {}", principal.getName(), project.get().getName());
                return new ResponseEntity<>(HttpStatus.OK);
            }
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
    }
    @Transactional
    public ResponseEntity<Status> iaasApiDelete(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            Optional<IaasApi> api = project.get().getIaasApis().stream().findFirst();
            if (api.isPresent() && api.get().getProject() == project.get()) {
                deleteIaasApiService.delete(api.get());
                log.info("{} - deleted IaasApi for project {}", principal.getName(), project.get().getName());
                return new ResponseEntity<>(HttpStatus.OK);
            }
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
    }

    public ResponseEntity<List<IaasApiType>> getIaasApiTypes(Principal principal) {
        return new ResponseEntity<>(getOrCreateIaasApiService.findAllTypes(),HttpStatus.OK);
    }
}
