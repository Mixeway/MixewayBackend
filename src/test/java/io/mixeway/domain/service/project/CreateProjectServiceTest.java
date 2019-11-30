package io.mixeway.domain.service.project;

import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.springframework.test.context.junit4.SpringRunner;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.ProjectRepository;


@RunWith(SpringRunner.class)
public class CreateProjectServiceTest {

    @Mock
    private ProjectRepository projectRepository;

    @Captor
    private ArgumentCaptor<Project> projectCaptor;

    @Test
    public void should_call_repository_with_unchanged_project_name_and_ciid() {
        //given
        Mockito.when(projectRepository.save(ArgumentMatchers.any())).thenReturn(new Project());
        CreateProjectService createProjectService = new CreateProjectService(projectRepository);

        //when
        createProjectService.createProject("ProjectName","TestCiid");

        //then
        Mockito.verify(projectRepository).save(projectCaptor.capture());
        Project project = projectCaptor.getValue();
        Assertions.assertThat(project.getCiid()).isEqualTo("TestCiid");
        Assertions.assertThat(project.getName()).isEqualTo("ProjectName");
    }
}