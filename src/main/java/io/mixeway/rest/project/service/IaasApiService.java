package io.mixeway.rest.project.service;

import io.mixeway.db.entity.IaasApiType;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.IaasApiTypeRepisotory;
import io.mixeway.pojo.PermissionFactory;
import io.mixeway.rest.project.model.IaasApiPutModel;
import io.mixeway.rest.project.model.IaasModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import io.mixeway.db.entity.IaasApi;
import io.mixeway.db.repository.IaasApiRepository;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.pojo.Status;

import javax.transaction.Transactional;
import java.security.Principal;
import java.util.List;
import java.util.Optional;

@Service
public class IaasApiService {
    private static final Logger log = LoggerFactory.getLogger(IaasApiService.class);
    private final ProjectRepository projectRepository;
    private final IaasApiRepository iaasApiRepository;
    private final IaasApiTypeRepisotory iaasApiTypeRepisotory;
    private final PermissionFactory permissionFactory;
    private final io.mixeway.integrations.servicediscovery.service.IaasService iaasApiService;


    IaasApiService(ProjectRepository projectRepository, IaasApiTypeRepisotory iaasApiTypeRepisotory,
                   IaasApiRepository iaasApiRepository, io.mixeway.integrations.servicediscovery.service.IaasService iaasApiService,
                   PermissionFactory permissionFactory){
        this.projectRepository = projectRepository;
        this.iaasApiRepository = iaasApiRepository;
        this.iaasApiTypeRepisotory = iaasApiTypeRepisotory;
        this.iaasApiService = iaasApiService;
        this.permissionFactory = permissionFactory;
    }

    public ResponseEntity<IaasModel> showIaasApi(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
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
        Optional<Project> project = projectRepository.findById(id);
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

        Optional<Project> project = projectRepository.findById(id);
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
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            Optional<IaasApi> api = project.get().getIaasApis().stream().findFirst();
            if (api.isPresent() && api.get().getProject().getId().equals(project.get().getId()) && api.get().getStatus()) {
                api.get().setEnabled(true);
                iaasApiRepository.save(api.get());
                log.info("{} - Enabled auto synchro of IaasApi for project {}", principal.getName(), project.get().getName());
                return new ResponseEntity<>(HttpStatus.OK);
            }
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
    }

    public ResponseEntity<Status> iaasApiDisableSynchro(Long id, Principal principal) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            Optional<IaasApi> api = project.get().getIaasApis().stream().findFirst();
            if (api.isPresent() && api.get().getProject().getId().equals(project.get().getId())) {
                api.get().setEnabled(false);
                iaasApiRepository.save(api.get());
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
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            Optional<IaasApi> api = project.get().getIaasApis().stream().findFirst();
            if (api.isPresent() && api.get().getProject() == project.get()) {
                iaasApiRepository.delete(api.get());
                log.info("{} - deleted IaasApi for project {}", principal.getName(), project.get().getName());
                return new ResponseEntity<>(HttpStatus.OK);
            }
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
    }

    public ResponseEntity<List<IaasApiType>> getIaasApiTypes(Principal principal) {
        return new ResponseEntity<>(iaasApiTypeRepisotory.findAll(),HttpStatus.OK);
    }
}
