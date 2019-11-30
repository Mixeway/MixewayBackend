package io.mixeway.rest.project.service;

import io.mixeway.db.entity.Project;
import io.mixeway.rest.project.model.ApiKeyResponse;
import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.*;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import io.mixeway.config.TestConfig;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.UserRepository;

import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceContextType;
import java.util.Optional;


@RunWith(SpringRunner.class)
@SpringBootTest
@ContextConfiguration(classes = {TestConfig.class})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@ActiveProfiles("DaoTest")
@PersistenceContext(type = PersistenceContextType.EXTENDED)
public class ApiAccessServiceTest {
    @Autowired
    ProjectRepository projectRepository;
    @Autowired
    UserRepository userRepository;
    private ApiAccessService apiAccessService;
    @Before
    public void setUp(){
        apiAccessService = new ApiAccessService(projectRepository);
    }



    @Test
    public void generateApiKey() {
        Project project = new Project();
        project.setName("tes");
        project = projectRepository.save(project);
        ResponseEntity<ApiKeyResponse> response = apiAccessService.generateApiKey(project.getId(),"test");
        project = projectRepository.getOne(project.getId());

        Assertions.assertThat(project.getApiKey()).isNotEmpty();
        Assertions.assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void deleteApiKey() {
        Project project = new Project();
        project.setName("tes2");
        project = projectRepository.save(project);
        apiAccessService.deleteApiKey(project.getId(),"test");
        Optional<Project> deletedProject = projectRepository.findById(project.getId());
        Assertions.assertThat(deletedProject.get().getApiKey()).isNull();
    }

    @Test
    public void getApiKey() {
        Project project = new Project();
        project.setName("tes3");
        project.setApiKey("test");
        project = projectRepository.save(project);
        ResponseEntity<ApiKeyResponse> status = apiAccessService.getApiKey(project.getId());
        Assertions.assertThat(status.getBody().getApiKey()).isNotBlank();

    }
}
