package io.mixeway.domain.service.project;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.springframework.test.context.junit4.SpringRunner;

import static java.util.Optional.of;
import static org.mockito.Mockito.*;

@RunWith(SpringRunner.class)
public class GetOrCxCreateProjectServiceTest {

    @Mock
    private FindProjectService findProjectService;

    @Mock
    private CreateProjectService createProjectService;

}