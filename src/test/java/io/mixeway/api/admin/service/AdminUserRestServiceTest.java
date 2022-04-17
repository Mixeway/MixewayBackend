package io.mixeway.api.admin.service;

import io.mixeway.api.admin.model.EditUserModel;
import io.mixeway.api.protocol.user.UserModel;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.UserRepository;
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
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AdminUserRestServiceTest {
    private final AdminUserRestService adminUserRestService;
    private final UserRepository userRepository;

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
        Mockito.when(principal.getName()).thenReturn("admin_user");
        User userToCreate = new User();
        userToCreate.setUsername("admin_user");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
    }

    @Test
    @Order(2)
    void showUsers() {

        ResponseEntity<List<User>> listResponseEntity = adminUserRestService.showUsers();
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
        assertTrue(listResponseEntity.getBody().size()>0);
    }

    @Test
    @Order(1)
    void addUser() {
        Mockito.when(principal.getName()).thenReturn("admin_user");
        UserModel userModel = UserModel.builder()
                .userRole("ROLE_USER")
                .userCN("test_user")
                .userUsername("test_user")
                .passwordAuth(true)
                .userPassword("pas")
                .build();
        ResponseEntity<Status> statusResponseEntity = adminUserRestService.addUser(userModel, "admin_user");
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        Optional<User> user= userRepository.findByUsername("test_user");
        assertTrue(user.isPresent());
    }

    @Test
    @Order(4)
    void enableUser() {
        Optional<User> user= userRepository.findByUsername("test_user");
        assertTrue(user.isPresent());
        ResponseEntity<Status> statusResponseEntity = adminUserRestService.enableUser(user.get().getId(), "admin_user");
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        user= userRepository.findByUsername("test_user");
        assertTrue(user.get().getEnabled());
    }

    @Test
    @Order(3)
    void disableUser() {

        Optional<User> user= userRepository.findByUsername("test_user");
        assertTrue(user.isPresent());
        ResponseEntity<Status> statusResponseEntity = adminUserRestService.disableUser(user.get().getId(), "admin_user");
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        user= userRepository.findByUsername("test_user");
        assertFalse(user.get().getEnabled());
    }

    @Test
    @Order(5)
    void editUser() {
        Optional<User> user= userRepository.findByUsername("test_user");
        assertTrue(user.isPresent());
        EditUserModel userModel = new EditUserModel();
        userModel.setRole("ROLE_ADMIN");
        adminUserRestService.editUser(user.get().getId(), userModel,"admin_user");
        user= userRepository.findByUsername("test_user");
        assertEquals("ROLE_ADMIN", user.get().getPermisions());
    }

    @Test
    @Order(6)
    void showProjects() {


        ResponseEntity<List<Project>> listResponseEntity = adminUserRestService.showProjects();
        assertEquals(HttpStatus.OK, listResponseEntity.getStatusCode());
    }
}