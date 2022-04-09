package io.mixeway.domain.service.user;

import io.mixeway.api.admin.model.EditUserModel;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.Principal;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EditUserServiceTest {

    private final EditUserService editUserService;
    private final FindUserService findUserService;
    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;

    @Mock
    Principal principal;

    @BeforeAll
    private void prepareDB() {
        Mockito.when(principal.getName()).thenReturn("edit_user");
        User userToCreate = new User();
        userToCreate.setUsername("edit_user");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
    }
    @Test
    void enable() {
        Optional<User> user = findUserService.findByUsername("edit_user");
        assertTrue(user.isPresent());
        editUserService.enable(user.get());
        user = findUserService.findByUsername("edit_user");
        assertTrue(user.isPresent());
        assertTrue(user.get().getEnabled());
    }

    @Test
    void disable() {

        Optional<User> user = findUserService.findByUsername("edit_user");
        assertTrue(user.isPresent());
        editUserService.disable(user.get());
        user = findUserService.findByUsername("edit_user");
        assertTrue(user.isPresent());
        assertFalse(user.get().getEnabled());
    }

    @Test
    void edit() {
        Optional<User> user = findUserService.findByUsername("edit_user");
        assertTrue(user.isPresent());
        EditUserModel editUserModel = new EditUserModel();
        editUserModel.setRole("ROLE_USER");

        editUserService.edit(user.get(), editUserModel);
        user = findUserService.findByUsername("edit_user");
        assertTrue(user.isPresent());
        assertEquals("ROLE_USER", user.get().getPermisions());
    }
}