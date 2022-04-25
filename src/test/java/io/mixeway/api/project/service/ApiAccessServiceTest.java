package io.mixeway.api.project.service;

import io.mixeway.api.project.model.ApiKeyResponse;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.scanmanager.integrations.openvas.apiclient.OpenVasApiClient;
import io.mixeway.scheduler.CodeScheduler;
import io.mixeway.scheduler.GlobalScheduler;
import io.mixeway.scheduler.NetworkScanScheduler;
import io.mixeway.scheduler.WebAppScheduler;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.*;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.security.Principal;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ApiAccessServiceTest {
    private final ApiAccessService apiAccessService;
    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;

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

    @BeforeAll
    private void prepareDB() {
        Mockito.when(principal.getName()).thenReturn("api_access_service");
        User userToCreate = new User();
        userToCreate.setUsername("api_access_service");
        userToCreate.setCommonName("api_access_service");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
        Project project = getOrCreateProjectService.getProjectId("api_access_service","api_access_service",principal);
    }

    @Test
    @Order(1)
    void generateApiKey() {
        Mockito.when(principal.getName()).thenReturn("api_access_service");
        Project project = getOrCreateProjectService.getProjectId("api_access_service","api_access_service",principal);
        ResponseEntity<ApiKeyResponse> apiKeyResponseResponseEntity = apiAccessService.generateApiKey(project.getId(),principal);
        assertEquals(HttpStatus.OK,apiKeyResponseResponseEntity.getStatusCode());
        assertNotNull(apiKeyResponseResponseEntity.getBody());
        assertNotNull(apiKeyResponseResponseEntity.getBody().getApiKey());
    }

    @Test
    @Order(3)
    void deleteApiKey() {
        Mockito.when(principal.getName()).thenReturn("api_access_service");
        Project project = getOrCreateProjectService.getProjectId("api_access_service","api_access_service",principal);
        ResponseEntity<Status> apiKeyResponseResponseEntity = apiAccessService.deleteApiKey(project.getId(),principal);
        assertEquals(HttpStatus.OK,apiKeyResponseResponseEntity.getStatusCode());
        project = getOrCreateProjectService.getProjectId("api_access_service","api_access_service",principal);
        assertNull(project.getApiKey());

    }

    @Test
    @Order(2)
    void getApiKey() {
        Mockito.when(principal.getName()).thenReturn("api_access_service");
        Project project = getOrCreateProjectService.getProjectId("api_access_service","api_access_service",principal);
        ResponseEntity<ApiKeyResponse> apiKeyResponseResponseEntity = apiAccessService.getApiKey(project.getId(),principal);
        assertEquals(HttpStatus.OK,apiKeyResponseResponseEntity.getStatusCode());
        assertNotNull(apiKeyResponseResponseEntity.getBody());
        assertNotNull(apiKeyResponseResponseEntity.getBody().getApiKey());

    }
}