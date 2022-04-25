package io.mixeway.api.project.service;

import io.mixeway.api.project.model.IaasApiPutModel;
import io.mixeway.api.project.model.IaasModel;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.IaasApi;
import io.mixeway.db.entity.IaasApiType;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.IaasApiRepository;
import io.mixeway.db.repository.IaasApiTypeRepisotory;
import io.mixeway.db.repository.RoutingDomainRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.iaasapi.GetOrCreateIaasApiService;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.routingdomain.CreateOrGetRoutingDomainService;
import io.mixeway.scheduler.CodeScheduler;
import io.mixeway.scheduler.GlobalScheduler;
import io.mixeway.scheduler.NetworkScanScheduler;
import io.mixeway.scheduler.WebAppScheduler;
import io.mixeway.servicediscovery.plugin.aws.apiclient.AwsApiClient;
import io.mixeway.utils.Status;
import io.mixeway.utils.VaultHelper;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.*;
import org.keycloak.authorization.client.util.Http;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.security.Principal;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class IaasApiServiceTest {
    private final IaasApiService iaasApiService;
    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final IaasApiRepository iaasApiRepository;
    private final IaasApiTypeRepisotory iaasApiTypeRepisotory;
    private final RoutingDomainRepository routingDomainRepository;
    private final VaultHelper vaultHelper;
    private final CreateOrGetRoutingDomainService createOrGetRoutingDomainService;

    @Mock
    Principal principal;

    @MockBean
    GlobalScheduler globalScheduler;

    @MockBean
    NetworkScanScheduler networkScheduler;

    @MockBean
    CodeScheduler codeScheduler;

    @MockBean
    WebAppScheduler webAppScheduler;

    @MockBean
    AwsApiClient awsApiClient;

    @BeforeAll
    private void prepareDB() {
        Mockito.when(principal.getName()).thenReturn("iaasapiservice");
        User userToCreate = new User();
        userToCreate.setUsername("iaasapiservice");
        userToCreate.setCommonName("iaasapiservice");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
    }

    @Test
    @Order(2)
    void showIaasApi() {
        Mockito.when(principal.getName()).thenReturn("iaasapiservice");
        Project project = getOrCreateProjectService.getProjectId("iaas_api","iaas_api",principal);

        ResponseEntity<IaasModel> optionalResponseEntity = iaasApiService.showIaasApi(project.getId(),principal);
        assertEquals(HttpStatus.OK, optionalResponseEntity.getStatusCode());
        assertNotNull(optionalResponseEntity.getBody());
    }

    @Test
    @Order(1)
    void saveIaasApi() {
        Mockito.when(principal.getName()).thenReturn("iaasapiservice");
        Mockito.when(awsApiClient.canProcessRequest(Mockito.any(IaasApiPutModel.class))).thenReturn(true);

        Mockito.doCallRealMethod().when(awsApiClient).saveApi(Mockito.any(), Mockito.any());
        Project project = getOrCreateProjectService.getProjectId("iaas_api","iaas_api",principal);
        IaasApiPutModel iaasApiPutModel = new IaasApiPutModel();
        iaasApiPutModel.setApiType(Constants.IAAS_API_TYPE_AWS_EC2);
        iaasApiPutModel.setRoutingDomainForIaasApi(createOrGetRoutingDomainService.createOrGetRoutingDomain("default").getId());
        iaasApiPutModel.setIamApi("https://api");
        Mockito.doAnswer(i -> {
            this.saveApi(iaasApiPutModel,project);
            return null;
        }).when(awsApiClient).saveApi(Mockito.any(),Mockito.any());
        ResponseEntity<Status> iaasApiTypes = iaasApiService.saveIaasApi(project.getId(),iaasApiPutModel, principal);
        assertEquals(HttpStatus.CREATED, iaasApiTypes.getStatusCode());
        Optional<IaasApi> iaasApi = iaasApiRepository.findByProjectAndIaasApiType(project, iaasApiTypeRepisotory.findByName(Constants.IAAS_API_TYPE_AWS_EC2));
        assertTrue(iaasApi.isPresent());
        iaasApi.get().setStatus(true);
        iaasApiRepository.save(iaasApi.get());
    }

    @Test
    @Order(3)
    void testIaasApi() {

        Mockito.when(principal.getName()).thenReturn("iaasapiservice");
        Mockito.doNothing().when(awsApiClient).testApiClient(Mockito.any());
        Project project = getOrCreateProjectService.getProjectId("iaas_api","iaas_api",principal);
        Optional<IaasApi> iaasApi = iaasApiRepository.findByProjectAndIaasApiType(project, iaasApiTypeRepisotory.findByName(Constants.IAAS_API_TYPE_AWS_EC2));
        assertTrue(iaasApi.isPresent());

        ResponseEntity<Status> statusResponseEntity = iaasApiService.testIaasApi(project.getId(), principal);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());

    }

    @Test
    @Order(4)
    void iaasApiEnableSynchro() {
        Mockito.when(principal.getName()).thenReturn("iaasapiservice");
        Project project = getOrCreateProjectService.getProjectId("iaas_api","iaas_api",principal);

        ResponseEntity<Status> statusResponseEntity = iaasApiService.iaasApiEnableSynchro(project.getId(), principal);
        Optional<IaasApi> iaasApi = iaasApiRepository.findByProjectAndIaasApiType(project, iaasApiTypeRepisotory.findByName(Constants.IAAS_API_TYPE_AWS_EC2));
        assertTrue(iaasApi.isPresent());
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        assertTrue(iaasApi.get().getEnabled());


    }

    @Test
    @Order(5)
    void iaasApiDisableSynchro() {

        Mockito.when(principal.getName()).thenReturn("iaasapiservice");
        Project project = getOrCreateProjectService.getProjectId("iaas_api","iaas_api",principal);

        ResponseEntity<Status> statusResponseEntity = iaasApiService.iaasApiDisableSynchro(project.getId(), principal);
        Optional<IaasApi> iaasApi = iaasApiRepository.findByProjectAndIaasApiType(project, iaasApiTypeRepisotory.findByName(Constants.IAAS_API_TYPE_AWS_EC2));
        assertTrue(iaasApi.isPresent());
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        assertFalse(iaasApi.get().getEnabled());
    }

    @Test
    @Order(7)
    void iaasApiDelete() {
        Mockito.when(principal.getName()).thenReturn("iaasapiservice");
        Project project = getOrCreateProjectService.getProjectId("iaas_api","iaas_api",principal);

        ResponseEntity<Status> statusResponseEntity = iaasApiService.iaasApiDelete(project.getId(), principal);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());

        Optional<IaasApi> iaasApi = iaasApiRepository.findByProjectAndIaasApiType(project, iaasApiTypeRepisotory.findByName(Constants.IAAS_API_TYPE_AWS_EC2));
        assertFalse(iaasApi.isPresent());
    }

    @Test
    @Order(6)
    void getIaasApiTypes() {
        Mockito.when(principal.getName()).thenReturn("iaasapiservice");

        ResponseEntity<List<IaasApiType>> iaasApiTypes = iaasApiService.getIaasApiTypes(principal);
        assertEquals(HttpStatus.OK, iaasApiTypes.getStatusCode());
        assertNotNull( iaasApiTypes.getBody());
        assertTrue( iaasApiTypes.getBody().size() > 0);
    }

    public void saveApi(IaasApiPutModel iaasApiPutModel, Project project) {
        IaasApi iaasApi = new IaasApi();
        iaasApi.setEnabled(false);
        iaasApi.setStatus(false);
        iaasApi.setExternal(false);
        iaasApi.setProject(project);
        iaasApi.setTenantId(iaasApiPutModel.getProjectid());
        iaasApi.setRegion(iaasApiPutModel.getRegion());
        iaasApi.setUsername(iaasApiPutModel.getUsername());
        iaasApi.setIaasApiType(iaasApiTypeRepisotory.findByName(Constants.IAAS_API_TYPE_AWS_EC2));
        iaasApi.setRoutingDomain(routingDomainRepository.findById(iaasApiPutModel.getRoutingDomainForIaasApi()).get());
        iaasApiRepository.save(iaasApi);
        String uuidToken = UUID.randomUUID().toString();
        if (vaultHelper.savePassword(iaasApiPutModel.getPassword(), uuidToken)){
            iaasApi.setPassword(uuidToken);
        } else {
            iaasApi.setPassword(iaasApiPutModel.getPassword());
        }
        iaasApiRepository.save(iaasApi);
    }
}