package io.mixeway.scheduler;

import io.mixeway.api.project.service.OpenSourceService;
import io.mixeway.scanmanager.service.opensource.OpenSourceScanClient;
import io.mixeway.scanmanager.service.opensource.OpenSourceScanService;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;

@Component
@Transactional
@RequiredArgsConstructor
public class OpenSourceScheduler {
    private final OpenSourceScanService openSourceScanService;
    private final List<OpenSourceScanClient> openSourceScanClients;

//    @Scheduled(initialDelay=0,fixedDelay = 28800000)
//    public void autoDiscover() throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
//        for (OpenSourceScanClient openSourceScanClient : openSourceScanClients) {
//            if (openSourceScanClient.canProcessRequest()) {
//                openSourceScanClient.autoDiscovery();
//            }
//        }
//    }
}

