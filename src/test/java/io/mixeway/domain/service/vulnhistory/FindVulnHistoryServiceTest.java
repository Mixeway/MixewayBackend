package io.mixeway.domain.service.vulnhistory;

import io.mixeway.api.protocol.OverAllVulnTrendChartData;
import io.mixeway.api.protocol.SourceDetectionChartData;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.InterfaceRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.routingdomain.CreateOrGetRoutingDomainService;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.Principal;
import java.util.HashSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FindVulnHistoryServiceTest {
    private final FindVulnHistoryService findVulnHistoryService;
    private final CreateVulnHistoryService createVulnHistoryService;

    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;

    @Mock
    Principal principal;

    @BeforeAll
    private void prepareDB() {
        Mockito.when(principal.getName()).thenReturn("find_vulnhistory");
        User userToCreate = new User();
        userToCreate.setUsername("find_vulnhistory");
        userToCreate.setPermisions("ROLE_ADMIN");
        userToCreate.setProjects(new HashSet<>());
        userRepository.save(userToCreate);
    }

    @Test
    void getVulnTrendData() {
        Mockito.when(principal.getName()).thenReturn("find_vulnhistory");
        Project project = getOrCreateProjectService.getProjectId("find_vulnhistory","find_vulnhistory",principal);
        for (int i=0; i<5; i++){
            createVulnHistoryService.create(project,"2022-03-0"+i+" 12:00:00",3L,4L,5L,6L, 7L);
        }
        List<OverAllVulnTrendChartData> overAllVulnTrendChartData= findVulnHistoryService.getVulnTrendData(principal);
        assertTrue(overAllVulnTrendChartData.size()>0);
    }

    @Test
    void getSourceTrendData() {
        Mockito.when(principal.getName()).thenReturn("find_vulnhistory");
        Project project = getOrCreateProjectService.getProjectId("find_vulnhistory2","find_vulnhistory2",principal);
        for (int i=0; i<5; i++){
            createVulnHistoryService.create(project,"2022-03-0"+i+" 12:00:00",3L,4L,5L,6L, 7L);
        }
        SourceDetectionChartData sourceDetectionChartData = findVulnHistoryService.getSourceTrendData(principal);
        assertNotNull(sourceDetectionChartData);
        //assertTrue(sourceDetectionChartData.getCode() > 0);
    }
}