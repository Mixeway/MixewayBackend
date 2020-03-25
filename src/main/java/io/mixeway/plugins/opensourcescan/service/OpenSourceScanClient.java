package io.mixeway.plugins.opensourcescan.service;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.plugins.opensourcescan.model.Projects;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;

public interface OpenSourceScanClient {
    boolean canProcessRequest(CodeProject codeProject);
    boolean canProcessRequest();
    void loadVulnerabilities(CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException;
    boolean createProject(CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException;
    List<Projects> getProjects() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException;
}
