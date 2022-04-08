package io.mixeway.utils;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.junit4.SpringRunner;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@RunWith(SpringRunner.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class VaultHelperTest {

    VaultHelper vaultHelper = new VaultHelper("default","");

    @Test
    void savePassword() {
        assertFalse(vaultHelper.savePassword("test", "dummy_token"));
    }

    @Test
    void getPassword() {
        String pswd = "secret";
        assertEquals(vaultHelper.getPassword(pswd), pswd);
    }
}