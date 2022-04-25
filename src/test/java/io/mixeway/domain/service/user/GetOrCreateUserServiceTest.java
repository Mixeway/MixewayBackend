package io.mixeway.domain.service.user;

import io.mixeway.api.protocol.user.UserModel;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.domain.exceptions.NotValidRoleException;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
class GetOrCreateUserServiceTest {
    private final GetOrCreateUserService getOrCreateUserService;
    private final FindUserService findUserService;
    private final ProjectRepository projectRepository;

    @Test
    void getOrCreateUser() throws NotValidRoleException {

        getOrCreateUserService.getOrCreateUser(UserModel.builder()
                .userUsername("get_or_create_user")
                .userCN("get_or_create_user")
                .userPassword("test")
                .userRole("ROLE_USER")
                .passwordAuth(false)
                .build());
        Optional<User> user = findUserService.findByUsername("get_or_create_user");
        assertTrue(user.isPresent());

    }

    @Test
    void loadProjectPermissionsForUser() throws NotValidRoleException {
        Project project = new Project();
        project.setName("test_get_user");
        project = projectRepository.saveAndFlush(project);
        List<Long> projectIds = new ArrayList<>();
        projectIds.add(project.getId());
        getOrCreateUserService.getOrCreateUser(UserModel.builder()
                .userUsername("get_or_create_user2")
                .userCN("get_or_create_user2")
                .userPassword("test")
                .passwordAuth(false)
                .userRole("ROLE_USER")
                .build());
        Optional<User> user = findUserService.findByUsername("get_or_create_user2");
        assertTrue(user.isPresent());
        getOrCreateUserService.loadProjectPermissionsForUser(projectIds,user.get());
        user = findUserService.findByUsername("get_or_create_user2");
        assertTrue(user.isPresent());
        assertTrue(user.get().getProjects().size()>0);
    }
}