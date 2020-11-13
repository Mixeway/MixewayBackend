package io.mixeway.rest.vulnmanage.controller;

import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.WebApp;
import io.mixeway.db.repository.AssetRepository;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.db.repository.InterfaceRepository;
import io.mixeway.db.repository.WebAppRepository;
import io.mixeway.pojo.Status;
import io.mixeway.test.authorization.BypassJwt;
import io.restassured.RestAssured;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.Arrays;
import java.util.List;

import static io.mixeway.test.authorization.HeaderSupplier.jwtHeader;
import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
@ActiveProfiles("test")
@BypassJwt
public class ScanManagerControllerTest {

    @MockBean
    private InterfaceRepository interfaceRepository;

    @MockBean
    private AssetRepository assetRepository;

    @MockBean
    private CodeProjectRepository codeProjectRepository;

    @MockBean
    private WebAppRepository webAppRepository;

    @Before
    public void setUp() {
        RestAssured.port = 8888;
    }

    @Test
    public void shouldReturn400WhenRequestHasInvalidFormat() {
        RestAssured
                .given()
                    .header(jwtHeader())
                .when()
                    .get("/v2/api/scanmanage/check/123")
                .then()
                    .statusCode(400);
    }

    @Test
    public void shouldReturn404WhenNoStatusIsFound() {
        RestAssured
                .given()
                    .header(jwtHeader())
                .when()
                    .get("/v2/api/scanmanage/check/da12412c-7376-4eff-a1e8-4569349154a1")
                .then()
                    .statusCode(404);
    }

    @Test
    public void shouldReturnStatusRunningWhenInterfaceEntityIsRunning() {
        String requestId = "da12412c-7376-4eff-a1e8-4569349154a1";
        List<Asset> assets = Arrays.asList(new Asset());
        Mockito.when(assetRepository.findByRequestId(requestId)).thenReturn(assets);

        Interface interfaceEntity = new Interface();
        interfaceEntity.setScanRunning(true);
        Mockito.when(interfaceRepository.findByAssetIn(assets)).thenReturn(Arrays.asList(interfaceEntity));

        Status status = RestAssured
                .given()
                    .header(jwtHeader())
                .when()
                    .get("/v2/api/scanmanage/check/da12412c-7376-4eff-a1e8-4569349154a1")
                .then()
                    .statusCode(200)
                .extract()
                    .as(Status.class);

        assertThat(status.getRequestId()).isEqualToIgnoringCase(requestId);
        assertThat(status.getStatus()).isEqualToIgnoringCase("Running");
    }

    @Test
    public void shouldReturnStatusRunningWhenCodeProjectEntityIsRunning() {
        String requestId = "da12412c-7376-4eff-a1e8-4569349154a1";
        CodeProject codeProject = new CodeProject();
        codeProject.setRunning(true);
        Mockito.when(codeProjectRepository.findByRequestId(requestId)).thenReturn(Arrays.asList(codeProject));

        Status status = RestAssured
                .given()
                    .header(jwtHeader())
                .when()
                    .get("/v2/api/scanmanage/check/da12412c-7376-4eff-a1e8-4569349154a1")
                .then()
                    .statusCode(200)
                .extract()
                    .as(Status.class);

        assertThat(status.getRequestId()).isEqualToIgnoringCase(requestId);
        assertThat(status.getStatus()).isEqualToIgnoringCase("Running");
    }

    @Test
    public void shouldReturnStatusQueuedWhenCodeProjectEntityIsQueued() {
        String requestId = "da12412c-7376-4eff-a1e8-4569349154a1";
        CodeProject codeProject = new CodeProject();
        codeProject.setInQueue(true);
        codeProject.setRunning(false);
        Mockito.when(codeProjectRepository.findByRequestId(requestId)).thenReturn(Arrays.asList(codeProject));

        Status status = RestAssured
                .given()
                    .header(jwtHeader())
                .when()
                    .get("/v2/api/scanmanage/check/da12412c-7376-4eff-a1e8-4569349154a1")
                .then()
                    .statusCode(200)
                .extract()
                    .as(Status.class);

        assertThat(status.getRequestId()).isEqualToIgnoringCase(requestId);
        assertThat(status.getStatus()).isEqualToIgnoringCase("In Queue");
    }

    @Test
    public void shouldReturnStatusRunningWhenWebappEntityIsRunning() {
        String requestId = "da12412c-7376-4eff-a1e8-4569349154a1";
        WebApp webApp = new WebApp();
        webApp.setRunning(true);
        Mockito.when(webAppRepository.findByRequestId(requestId)).thenReturn(Arrays.asList(webApp));

        Status status = RestAssured
                .given()
                    .header(jwtHeader())
                .when()
                    .get("/v2/api/scanmanage/check/da12412c-7376-4eff-a1e8-4569349154a1")
                .then()
                    .statusCode(200)
                .extract()
                    .as(Status.class);

        assertThat(status.getRequestId()).isEqualToIgnoringCase(requestId);
        assertThat(status.getStatus()).isEqualToIgnoringCase("Running");
    }

    @Test
    public void shouldReturnStatusRunningWhenWebappEntityIsQueued() {
        String requestId = "da12412c-7376-4eff-a1e8-4569349154a1";
        WebApp webApp = new WebApp();
        webApp.setRunning(false);
        webApp.setInQueue(true);
        Mockito.when(webAppRepository.findByRequestId(requestId)).thenReturn(Arrays.asList(webApp));

        Status status = RestAssured
                .given()
                    .header(jwtHeader())
                .when()
                    .get("/v2/api/scanmanage/check/da12412c-7376-4eff-a1e8-4569349154a1")
                .then()
                    .statusCode(200)
                .extract()
                    .as(Status.class);

        assertThat(status.getRequestId()).isEqualToIgnoringCase(requestId);
        assertThat(status.getStatus()).isEqualToIgnoringCase("In Queue");
    }

    @Test
    public void shouldReturnStatusDoneWhenThereIsNoRunningOrQueuedEntities() {
        String requestId = "da12412c-7376-4eff-a1e8-4569349154a1";
        WebApp webApp = new WebApp();
        webApp.setRunning(false);
        webApp.setInQueue(false);
        Mockito.when(webAppRepository.findByRequestId(requestId)).thenReturn(Arrays.asList(webApp));

        Status status = RestAssured
                .given()
                    .header(jwtHeader())
                .when()
                    .get("/v2/api/scanmanage/check/da12412c-7376-4eff-a1e8-4569349154a1")
                .then()
                    .statusCode(200)
                .extract()
                    .as(Status.class);

        assertThat(status.getRequestId()).isEqualToIgnoringCase(requestId);
        assertThat(status.getStatus()).isEqualToIgnoringCase("Done");
    }
}