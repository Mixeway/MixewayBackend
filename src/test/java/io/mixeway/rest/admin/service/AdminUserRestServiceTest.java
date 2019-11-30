package io.mixeway.rest.admin.service;

import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import io.mixeway.config.TestConfig;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.pojo.Status;
import io.mixeway.rest.model.NewPasswordModel;
import io.mixeway.rest.model.UserModel;

import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceContextType;
import javax.transaction.Transactional;

import java.util.List;

@RunWith(SpringRunner.class)
@SpringBootTest
@ContextConfiguration(classes = {TestConfig.class})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@ActiveProfiles("DaoTest")
@PersistenceContext(type = PersistenceContextType.EXTENDED)
@Transactional
public class AdminUserRestServiceTest {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private AdminUserRestService adminUserRestService;

    @Before
    public void setUp(){
        adminUserRestService = new AdminUserRestService(userRepository,bCryptPasswordEncoder);
    }

    @Test
    public void showUsers() {
        User user = new User();
        user.setCommonName("test");
        user.setPermisions("ROLE_USER");
        user.setUsername("test");
        userRepository.save(user);
        ResponseEntity<List<User>> result = adminUserRestService.showUsers();
        Assertions.assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        Assertions.assertThat(result.getBody().size()).isGreaterThan(0);
    }

    @Test
    public void addUser() {
        UserModel userModel = new UserModel();
        userModel.setPasswordAuth(true);
        userModel.setUserPassword("jajaja");
        userModel.setUserRole("ROLE_USER");
        userModel.setUserUsername("test");
        ResponseEntity<Status> result = adminUserRestService.addUser(userModel, "test");
        Assertions.assertThat(result.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    @Test
    public void enableUser() {
        User user = new User();
        user.setCommonName("test");
        user.setPermisions("ROLE_USER");
        user.setUsername("test");
        user = userRepository.save(user);
        ResponseEntity<Status> result = adminUserRestService.enableUser(user.getId(),"test");
        Assertions.assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        result = adminUserRestService.enableUser(666L,"test");
        Assertions.assertThat(result.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    public void disableUser() {
        User user = new User();
        user.setCommonName("test");
        user.setPermisions("ROLE_USER");
        user.setUsername("test");
        user = userRepository.save(user);
        ResponseEntity<Status> result = adminUserRestService.disableUser(user.getId(),"test");
        Assertions.assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        result = adminUserRestService.disableUser(666L,"test");
        Assertions.assertThat(result.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    public void editUser() {
        User user = new User();
        user.setCommonName("test");
        user.setPermisions("ROLE_USER");
        user.setUsername("test");
        user = userRepository.save(user);
        NewPasswordModel userModel = new NewPasswordModel();
        userModel.setNewPassword("Test");
        ResponseEntity<Status> result = adminUserRestService.editUser(user.getId(),userModel, "test");
        Assertions.assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        result = adminUserRestService.editUser(666L,userModel,"test");
        Assertions.assertThat(result.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);


    }
}