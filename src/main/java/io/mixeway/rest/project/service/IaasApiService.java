package io.mixeway.rest.project.service;

import io.mixeway.db.entity.Project;
import io.mixeway.rest.project.model.IaasApiPutModel;
import io.mixeway.rest.project.model.IaasModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultOperations;
import io.mixeway.db.entity.IaasApi;
import io.mixeway.db.repository.IaasApiRepository;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.RoutingDomainRepository;
import io.mixeway.plugins.servicediscovery.openstack.apiclient.OpenStackApiClient;
import io.mixeway.pojo.Status;

import javax.transaction.Transactional;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
public class IaasApiService {
    private static final Logger log = LoggerFactory.getLogger(IaasApiService.class);
    private final ProjectRepository projectRepository;
    private final RoutingDomainRepository routingDomainRepository;
    private final IaasApiRepository iaasApiRepository;
    private final VaultOperations operations;
    private final OpenStackApiClient openStackApiClient;

    @Autowired
    IaasApiService(ProjectRepository projectRepository, RoutingDomainRepository routingDomainRepository,
                   IaasApiRepository iaasApiRepository, VaultOperations operations, OpenStackApiClient openStackApiClient){
        this.projectRepository = projectRepository;
        this.routingDomainRepository = routingDomainRepository;
        this.iaasApiRepository = iaasApiRepository;
        this.openStackApiClient = openStackApiClient;
        this.operations = operations;
    }

    public ResponseEntity<IaasModel> showIaasApi(Long id) {
        Optional<Project> project = projectRepository.findById(id);
        if ( project.isPresent() && project.get().getIaasApis().size() == 1){
            Optional<IaasApi> iaasApi = project.get().getIaasApis().stream().findFirst();
            IaasModel iaasModel = new IaasModel();
            iaasModel.setAuto(iaasApi.get().getEnabled());
            iaasModel.setEnabled(iaasApi.get().getStatus());
            iaasModel.setIam(iaasApi.get().getIamUrl());
            iaasModel.setService(iaasApi.get().getServiceUrl());
            iaasModel.setNetwork(iaasApi.get().getNetworkUrl());
            iaasModel.setProject(iaasApi.get().getTenantId());
            return new ResponseEntity<>(iaasModel, HttpStatus.OK);

        } else if (project.isPresent()) {
            return new ResponseEntity<>(new IaasModel(),HttpStatus.OK);
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> saveIaasApi(Long id, IaasApiPutModel iaasApiPutModel, String username) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()){
            if (project.get().getIaasApis().size() >0){
                return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
            } else {
                IaasApi iaasApi = new IaasApi();
                iaasApi.setIamUrl(iaasApiPutModel.getIamApi());
                iaasApi.setServiceUrl(iaasApiPutModel.getServiceApi());
                iaasApi.setNetworkUrl(iaasApiPutModel.getNetworkApi());
                iaasApi.setTenantId(iaasApiPutModel.getProjectid());
                iaasApi.setUsername(iaasApiPutModel.getUsername());
                iaasApi.setRoutingDomain(routingDomainRepository.getOne(iaasApiPutModel.getRoutingDomainForIaasApi()));
                iaasApi.setPassword(UUID.randomUUID().toString());
                iaasApi.setProject(project.get());
                iaasApi.setEnabled(false);
                iaasApi.setStatus(false);
                iaasApi.setExternal(false);
                iaasApiRepository.save(iaasApi);
                Map<String, String> mapa = new HashMap<>();
                mapa.put("password", iaasApiPutModel.getPassword());
                operations.write("secret/"+iaasApi.getPassword(), mapa);
                log.info("{} - Saved new IaasApi for project {}", username, project.get().getName());
                return new ResponseEntity<>(new Status("ok"), HttpStatus.CREATED);
            }
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> testIaasApi(Long id) {

        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()){
            Optional<IaasApi> api = project.get().getIaasApis().stream().findFirst();
            if (api.isPresent() && api.get().getProject() == project.get()) {
                try {
                    openStackApiClient.sendAuthRequest(api.get());
                } catch (Exception e) {
                    return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
                }
                return new ResponseEntity<>(new Status("ok"), HttpStatus.OK);
            }
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
        return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
    }

    public ResponseEntity<Status> iaasApiEnableSynchro(Long id, String username) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()){
            Optional<IaasApi> api = project.get().getIaasApis().stream().findFirst();
            if (api.isPresent() && api.get().getProject() == project.get()) {
                api.get().setEnabled(true);
                iaasApiRepository.save(api.get());
                log.info("{} - Enabled auto synchro of IaasApi for project {}", username, project.get().getName());
                return new ResponseEntity<>(null,HttpStatus.OK);
            }
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
        return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
    }

    public ResponseEntity<Status> iaasApiDisableSynchro(Long id, String username) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()){
            Optional<IaasApi> api = project.get().getIaasApis().stream().findFirst();
            if (api.isPresent() && api.get().getProject() == project.get()) {
                api.get().setEnabled(false);
                iaasApiRepository.save(api.get());
                log.info("{} - Disabled auto synchro of IaasApi for project {}", username, project.get().getName());
                return new ResponseEntity<>(null,HttpStatus.OK);
            }
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
        return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
    }
    @Transactional
    public ResponseEntity<Status> iaasApiDelete(Long id, String username) {
        Optional<Project> project = projectRepository.findById(id);
        if (project.isPresent()){
            Optional<IaasApi> api = project.get().getIaasApis().stream().findFirst();
            if (api.isPresent() && api.get().getProject() == project.get()) {
                iaasApiRepository.delete(api.get());
                log.info("{} - deleted IaasApi for project {}", username, project.get().getName());
                return new ResponseEntity<>(null,HttpStatus.OK);
            }
        } else {
            return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
        }
        return new ResponseEntity<>(null,HttpStatus.EXPECTATION_FAILED);
    }

}
