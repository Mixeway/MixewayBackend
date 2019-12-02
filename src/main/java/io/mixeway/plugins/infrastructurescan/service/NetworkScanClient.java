package io.mixeway.plugins.infrastructurescan.service;

import org.codehaus.jettison.json.JSONException;
import io.mixeway.db.entity.NessusScan;
import io.mixeway.db.entity.Scanner;

import javax.xml.bind.JAXBException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public interface NetworkScanClient {
    boolean runScan(NessusScan nessusScan) throws JSONException, CertificateException, UnrecoverableKeyException,
            NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JAXBException;
    void runScanManual(NessusScan nessusScan) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException,
            KeyManagementException, JSONException, KeyStoreException, IOException, JAXBException;
    boolean isScanDone(NessusScan nessusScan) throws JSONException, CertificateException, UnrecoverableKeyException,
            NoSuchAlgorithmException, IOException, KeyStoreException, KeyManagementException, JAXBException;
    void loadVulnerabilities(NessusScan nessusScan) throws JSONException, CertificateException, UnrecoverableKeyException,
            NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JAXBException;
    boolean canProcessRequest(NessusScan nessusScan);
    boolean canProcessRequest(Scanner scanner);

}