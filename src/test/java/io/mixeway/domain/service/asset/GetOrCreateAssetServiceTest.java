package io.mixeway.domain.service.asset;

import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.Settings;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.routingdomain.CreateOrGetRoutingDomainService;
import io.mixeway.scanmanager.model.AssetToCreate;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.Principal;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class GetOrCreateAssetServiceTest {
    private final GetOrCreateAssetService getOrCreateAssetService;
    private final UserRepository userRepository;
    private final CreateOrGetRoutingDomainService createOrGetRoutingDomainService;
    private final GetOrCreateProjectService getOrCreateProjectService;

    @Mock
    Principal principal;

    @BeforeAll
    public void prepare(){
        User user = new User();
        user.setUsername("get_or_create_asset");
        user.setPermisions("ROLE_ADMIN");
        userRepository.save(user);
        Mockito.when(principal.getName()).thenReturn("get_or_create_asset");
        createOrGetRoutingDomainService.createOrGetRoutingDomain("default");
    }

    @Test
    void getOrCreateAsset() {
        Mockito.when(principal.getName()).thenReturn("get_or_create_asset");
        Project project = getOrCreateProjectService.getProjectId("create_asset","create_asset",principal);
        AssetToCreate assetToCreate = AssetToCreate.builder()
                .hostname("test")
                .ip("1.1.1.1")
                .routingDomain("default")
                .build();
        Asset asset = getOrCreateAssetService.getOrCreateAsset(assetToCreate,project,"gui");
        assertNotNull(asset);
        assertNotNull(asset.getId());

    }
    @Test
    void getOrCreateAsset2() {
        Mockito.when(principal.getName()).thenReturn("get_or_create_asset");
        Project project = getOrCreateProjectService.getProjectId("create_asset2","create_asset2",principal);
        Asset asset = getOrCreateAssetService.getOrCreateAsset("new_asset",createOrGetRoutingDomainService.createOrGetRoutingDomain("default"),project);
        assertNotNull(asset);
        assertNotNull(asset.getId());
    }
}