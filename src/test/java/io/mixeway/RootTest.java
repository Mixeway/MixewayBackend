package io.mixeway;

import io.restassured.RestAssured;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import static io.restassured.RestAssured.when;
/**
 * @author gsiewruk
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
@ActiveProfiles("test")
public class RootTest {

    @Before
    public void setUp() {
        RestAssured.port = 8888;
    }

    @Test
    public void checkAuthStatus(){
        when().request("GET", "/v2/auth/status").then().statusCode(200);
    }
}
