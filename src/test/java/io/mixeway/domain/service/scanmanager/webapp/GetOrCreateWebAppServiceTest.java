package io.mixeway.domain.service.scanmanager.webapp;

import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import io.mixeway.db.entity.WebApp;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.db.repository.WebAppRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.scanmanager.model.CustomCookie;
import io.mixeway.scanmanager.model.RequestHeaders;
import io.mixeway.scanmanager.model.WebAppScanModel;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.security.Principal;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class GetOrCreateWebAppServiceTest {
    private final GetOrCreateWebAppService getOrCreateWebAppService;
    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final WebAppRepository webAppRepository;

    @Mock
    Principal principal;

    @BeforeAll
    private void prepareDB() {
        Mockito.when(principal.getName()).thenReturn("get_or_create_webapp");
        User userToCreate = new User();
        userToCreate.setUsername("get_or_create_webapp");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
    }

    @Test
    void getOrCreateWebApp() throws ParseException {
        Mockito.when(principal.getName()).thenReturn("get_or_create_webapp");
        Project project = getOrCreateProjectService.getProjectId("get_or_create_webapp","get_or_create_webapp",principal);
        WebAppScanModel webAppScanModel = new WebAppScanModel();
        webAppScanModel.setUrl("https://url");
        webAppScanModel.setRoutingDomain("default");
        WebApp webApp = getOrCreateWebAppService.getOrCreateWebApp("https://url",project, webAppScanModel,"gui", "uuid");
        assertNotNull(webApp);
        assertEquals("https://url", webApp.getUrl());
        assertEquals("uuid", webApp.getRequestId());
    }

    @Test
    void createWebApp() {
        Mockito.when(principal.getName()).thenReturn("get_or_create_webapp");
        Project project = getOrCreateProjectService.getProjectId("get_or_create_webapp2","get_or_create_webapp2",principal);
        WebAppScanModel webAppScanModel = new WebAppScanModel();
        webAppScanModel.setUrl("https://urlxyz");
        webAppScanModel.setRoutingDomain("default");

        WebApp webApp = getOrCreateWebAppService.createWebApp("https://urlxyz",project,webAppScanModel,"gui","requestid");
        assertNotNull(webApp);
        assertEquals("https://urlxyz", webApp.getUrl());
        assertEquals("requestid", webApp.getRequestId());

    }

    @Test
    void createHeaderAndCookies() throws ParseException {
        Mockito.when(principal.getName()).thenReturn("get_or_create_webapp");
        Project project = getOrCreateProjectService.getProjectId("get_or_create_webapp2","get_or_create_webapp2",principal);
        WebAppScanModel webAppScanModel = new WebAppScanModel();
        webAppScanModel.setUrl("https://url3");
        webAppScanModel.setRoutingDomain("default");
        WebApp webApp = getOrCreateWebAppService.createWebApp("https://url3",project,webAppScanModel,"gui","requestid");
        List<RequestHeaders> headers = new ArrayList<>();
        List<CustomCookie> cookies = new ArrayList<>();
        for(int i = 0; i<5 ; i++){
            RequestHeaders requestHeaders = new RequestHeaders();
            requestHeaders.setHeaderName("test"+i);
            requestHeaders.setHeaderValue("value");
            headers.add(requestHeaders);
            CustomCookie cookie = new CustomCookie();
            cookie.setCookie("test"+i);
            cookie.setUrl("/");
            cookies.add(cookie);
        }

        getOrCreateWebAppService.createHeaderAndCookies(headers,cookies,webApp);
        webApp = getOrCreateWebAppService.getOrCreateWebApp("https://url3", project, null, null, null);
        assertEquals(5, webApp.getHeaders().size());
        assertEquals(5, webApp.getWebAppCookies().size());
    }

    @Test
    void checkRegexes() {
        Mockito.when(principal.getName()).thenReturn("get_or_create_webapp");
        Project project = getOrCreateProjectService.getProjectId("get_or_create_webapp3","get_or_create_webapp3",principal);
        WebAppScanModel webAppScanModel = new WebAppScanModel();
        webAppScanModel.setUrl("https://test.pl/2");
        webAppScanModel.setRoutingDomain("default");
        WebApp webApp = getOrCreateWebAppService.createWebApp("https://test.pl/2",project,webAppScanModel,"gui","requestid");
        List<WebApp>  webApps = getOrCreateWebAppService.checkRegexes("https://test.pl/[0-9]", project.getId());
        assertTrue(webApps.size() > 0);
    }

    @Test
    @Transactional
    void removeCookiesForWebApp() throws ParseException {
        Mockito.when(principal.getName()).thenReturn("get_or_create_webapp");
        Project project = getOrCreateProjectService.getProjectId("get_or_create_webapp4","get_or_create_webapp4",principal);
        WebAppScanModel webAppScanModel = new WebAppScanModel();
        webAppScanModel.setUrl("https://removec.pl/3");
        webAppScanModel.setRoutingDomain("default");
        WebApp webApp = getOrCreateWebAppService.createWebApp("https://removec.pl/3",project,webAppScanModel,"gui","requestid");
        List<RequestHeaders> headers = new ArrayList<>();
        List<CustomCookie> cookies = new ArrayList<>();
        for(int i = 0; i<5 ; i++){
            RequestHeaders requestHeaders = new RequestHeaders();
            requestHeaders.setHeaderName("test"+i);
            requestHeaders.setHeaderValue("value");
            headers.add(requestHeaders);
            CustomCookie cookie = new CustomCookie();
            cookie.setCookie("test"+i);
            cookie.setUrl("/");
            cookies.add(cookie);
        }

        getOrCreateWebAppService.createHeaderAndCookies(headers,cookies,webApp);
        getOrCreateWebAppService.removeCookiesForWebApp(webApp);
        webApp = getOrCreateWebAppService.getOrCreateWebApp("https://removec.pl/3",project,webAppScanModel,"gui","requestid");
        assertEquals(0, webApp.getWebAppCookies().size());
    }

    @Test
    @Transactional
    void removeHeadersForWebApp() throws ParseException {
        Mockito.when(principal.getName()).thenReturn("get_or_create_webapp");
        Project project = getOrCreateProjectService.getProjectId("get_or_create_webapp5","get_or_create_webapp5",principal);
        WebAppScanModel webAppScanModel = new WebAppScanModel();
        webAppScanModel.setUrl("https://removeh.pl/4");
        webAppScanModel.setRoutingDomain("default");
        WebApp webApp = getOrCreateWebAppService.createWebApp("https://removeh.pl/4",project,webAppScanModel,"gui","requestid");
        List<RequestHeaders> headers = new ArrayList<>();
        List<CustomCookie> cookies = new ArrayList<>();
        for(int i = 0; i<5 ; i++){
            RequestHeaders requestHeaders = new RequestHeaders();
            requestHeaders.setHeaderName("test"+i);
            requestHeaders.setHeaderValue("value");
            headers.add(requestHeaders);
            CustomCookie cookie = new CustomCookie();
            cookie.setCookie("test"+i);
            cookie.setUrl("/");
            cookies.add(cookie);
        }

        getOrCreateWebAppService.createHeaderAndCookies(headers,cookies,webApp);
        getOrCreateWebAppService.removeHeadersForWebApp(webApp);
        //webApp = getOrCreateWebAppService.getOrCreateWebApp("https://removeh.pl/4",project,webAppScanModel,"gui","requestid");
        webApp = webAppRepository.findByProjectAndUrl(project, "https://removeh.pl/4").get();
        assertEquals(0, webApp.getHeaders().size());
    }

    @Test
    @Transactional
    void createWebAppHeader() throws ParseException {
        Mockito.when(principal.getName()).thenReturn("get_or_create_webapp");
        Project project = getOrCreateProjectService.getProjectId("get_or_create_webapp6","get_or_create_webapp6",principal);
        WebAppScanModel webAppScanModel = new WebAppScanModel();
        webAppScanModel.setUrl("https://createh.pl/5");
        webAppScanModel.setRoutingDomain("default");
        WebApp webApp = getOrCreateWebAppService.createWebApp("https://createh.pl/5",project,webAppScanModel,"gui","requestid");
        getOrCreateWebAppService.createWebAppHeader("test","test",webApp);
        webApp = getOrCreateWebAppService.getOrCreateWebApp("https://createh.pl/5",project,webAppScanModel,"gui","requestid");
        assertEquals(1, webApp.getHeaders().size());
    }

    @Test
    @Transactional
    void createCookiesForWebApp() throws ParseException {
        Mockito.when(principal.getName()).thenReturn("get_or_create_webapp");
        Project project = getOrCreateProjectService.getProjectId("get_or_create_webapp7","get_or_create_webapp7",principal);
        WebAppScanModel webAppScanModel = new WebAppScanModel();
        webAppScanModel.setUrl("https://create.pl/6");
        webAppScanModel.setRoutingDomain("default");
        WebApp webApp = getOrCreateWebAppService.createWebApp("https://create.pl/6",project,webAppScanModel,"gui","requestid");
        CustomCookie cookie = new CustomCookie();
        cookie.setCookie("test");
        cookie.setUrl("/");
        getOrCreateWebAppService.createCookiesForWebApp(cookie,webApp);
        webApp = getOrCreateWebAppService.getOrCreateWebApp("https://create.pl/6",project,webAppScanModel,"gui","requestid");
        assertEquals(1, webApp.getWebAppCookies().size());
    }
}