package io.mixeway.api.auth.service;

import io.mixeway.api.admin.service.AdminUserRestService;
import io.mixeway.api.auth.model.Password;
import io.mixeway.api.auth.model.PasswordAuthModel;
import io.mixeway.api.auth.model.StatusEntity;
import io.mixeway.api.protocol.user.UserModel;
import io.mixeway.db.entity.Status;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.exceptions.NotValidRoleException;
import io.mixeway.scheduler.CodeScheduler;
import io.mixeway.scheduler.GlobalScheduler;
import io.mixeway.scheduler.NetworkScanScheduler;
import io.mixeway.scheduler.WebAppScheduler;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuthServiceTest {
    private final AuthService authService;
    private final UserRepository userRepository;
    private final AdminUserRestService adminUserRestService;

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
        User userToCreate = new User();
        userToCreate.setUsername("auth_service");
        userToCreate.setCommonName("auth_service");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
        adminUserRestService.addUser(UserModel.builder()
                .userPassword("test")
                .passwordAuth(true)
                .userCN("auth_service_user")
                .userUsername("auth_service_user")
                .userRole("ROLE_USER").build(), "auth_service");
    }

    @Test
    void init() {
        authService.init();
    }

    @Test
    void generateJWTTokenForUser() throws IOException {
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        HttpServletResponse response = ((ServletRequestAttributes)requestAttributes).getResponse();

        authService.generateJWTTokenForUser("auth_service", response);
        assert response != null;
        assertEquals("/pages/dashboard",response.getHeader("Location"));
    }

    @Test
    void processPasswordAuth() throws IOException {
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        HttpServletResponse response = ((ServletRequestAttributes)requestAttributes).getResponse();
        PasswordAuthModel passwordAuthModel = new PasswordAuthModel();
        passwordAuthModel.setPassword("test");
        passwordAuthModel.setUsername("auth_service_user");
        authService.processPasswordAuth(response, passwordAuthModel);
        assert response != null;
        assertNotNull(response.getHeader("Set-Cookie"));
    }

    @Test
    void initialize() throws NotValidRoleException {
        Password password = new Password();
        password.setPassword("12345678");

        ResponseEntity<Status> statusResponseEntity = authService.initialize(password);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
    }

    @Test
    void getStatus() {

        ResponseEntity<StatusEntity> statusResponseEntity = authService.getStatus();
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
    }

    @Test
    void getStatus2() {

        ResponseEntity<StatusEntity> statusResponseEntity = authService.getStatus2();
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());

    }

    @Test
    void proceedWithSocialLogin() throws NotValidRoleException, IOException {
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        assert requestAttributes != null;
        HttpServletResponse response = ((ServletRequestAttributes)requestAttributes).getResponse();
        assert response != null;
        authService.proceedWithSocialLogin("auth_service_user",response);
        assert response != null;
        assertEquals("test/pages/dashboard",response.getHeader("Location"));
    }

    @Test
    void processFbLogin() {

       //no idea how to test it yet
    }

    @Test
    void processGitHubLogin() {

        //no idea how to test it yet

    }

    @Test
    void authenticateFBUser() {

        //no idea how to test it yet
    }

    @Test
    void authenticateGitHubUser() {

        //no idea how to test it yet
    }

    @Test
    void authUsingKeycloak() {
        //no idea how to test it yet
    }
}