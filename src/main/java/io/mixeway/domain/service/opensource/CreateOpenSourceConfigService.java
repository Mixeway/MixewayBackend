package io.mixeway.domain.service.opensource;

import io.mixeway.api.protocol.OpenSourceConfig;
import io.mixeway.db.entity.Scanner;
import io.mixeway.scanmanager.model.SASTRequestVerify;
import io.mixeway.utils.VaultHelper;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class CreateOpenSourceConfigService {
    private final VaultHelper vaultHelper;

    public OpenSourceConfig create(SASTRequestVerify sastRequestVerify, Scanner openSourceScanner){
        OpenSourceConfig openSourceConfig = new OpenSourceConfig();
        if (StringUtils.isNotBlank(sastRequestVerify.getCp().getdTrackUuid()) && openSourceScanner != null){
            openSourceConfig.setOpenSourceScannerApiUrl(openSourceScanner.getApiUrl());
            openSourceConfig.setOpenSourceScannerCredentials(vaultHelper.getPassword(openSourceScanner.getApiKey()));
            openSourceConfig.setOpenSourceScannerProjectId(sastRequestVerify.getCp().getdTrackUuid());
            openSourceConfig.setTech(sastRequestVerify.getCp().getTechnique());
            openSourceConfig.setScannerType(openSourceScanner.getScannerType().getName());
            openSourceConfig.setOpenSourceScannerIntegration(true);
        } else {
            openSourceConfig.setOpenSourceScannerIntegration(false);
        }
        return openSourceConfig;
    }
}
