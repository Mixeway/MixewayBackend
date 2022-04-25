package io.mixeway.scanmanager.service.network;

import io.mixeway.db.entity.InfraScan;
import io.mixeway.db.entity.RoutingDomain;
import io.mixeway.db.entity.Scanner;
import org.codehaus.jettison.json.JSONException;

import javax.xml.bind.JAXBException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public interface NetworkScanClient {
    boolean runScan(InfraScan infraScan) throws Exception;
    void runScanManual(InfraScan infraScan) throws Exception;
    boolean isScanDone(InfraScan infraScan) throws JSONException, CertificateException, UnrecoverableKeyException,
            NoSuchAlgorithmException, IOException, KeyStoreException, KeyManagementException, JAXBException;
    void loadVulnerabilities(InfraScan infraScan) throws JSONException, CertificateException, UnrecoverableKeyException,
            NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JAXBException;
    boolean canProcessRequest(InfraScan infraScan);
    boolean canProcessRequest(Scanner scanner);
    boolean canProcessRequest(RoutingDomain routingDomain);
    Scanner getScannerFromClient(RoutingDomain routingDomain);
    String printInfo();

}
