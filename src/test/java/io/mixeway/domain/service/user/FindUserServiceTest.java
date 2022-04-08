package io.mixeway.domain.service.user;

import io.mixeway.db.entity.User;
import io.mixeway.db.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FindUserServiceTest {
    private final FindUserService findUserService;
    private final UserRepository userRepository;

    @BeforeAll
    private void prepareDB() {
        User userToCreate = new User();
        userToCreate.setUsername("find_user");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
    }

    @Test
    void findAll() {
        assertTrue(findUserService.findAll().size() > 0);

    }

    @Test
    void findById() {
        Optional<User> user = userRepository.findByUsername("find_user");
        assertTrue(user.isPresent());
        Optional<User> userFind = findUserService.findById(user.get().getId());
        assertTrue(userFind.isPresent());
        userFind = findUserService.findById(666L);
        assertFalse(userFind.isPresent());
    }
}