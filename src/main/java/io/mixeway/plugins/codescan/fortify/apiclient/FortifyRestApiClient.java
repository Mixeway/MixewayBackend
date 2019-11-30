package io.mixeway.plugins.codescan.fortify.apiclient;

import io.mixeway.db.repository.*;
import io.mixeway.pojo.SecureRestTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.vault.core.VaultOperations;

@Component
public class FortifyRestApiClient {
    @Autowired
    SecureRestTemplate secureRestTemplate;
    @Autowired
    ScannerRepository scannerRepository;
    @Autowired
    ScannerTypeRepository scannerTypeRepository;
    @Autowired
    VaultOperations operations;
    @Autowired
    CodeGroupRepository codeGroupRepository;
    @Autowired
    CodeProjectRepository codeProjectRepository;
    @Autowired
    FortifySingleAppRepository fortifySingleAppRepository;


    final static Logger log = LoggerFactory.getLogger(FortifyRestApiClient.class);




}
