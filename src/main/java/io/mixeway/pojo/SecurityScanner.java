package io.mixeway.pojo;

import io.mixeway.db.entity.Scanner;
import io.mixeway.rest.model.ScannerModel;
import org.codehaus.jettison.json.JSONException;
import io.mixeway.db.entity.ScannerType;

import javax.xml.bind.JAXBException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;

public interface SecurityScanner {
    boolean initialize(Scanner scanner) throws JSONException, ParseException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JAXBException, Exception;
    boolean canProcessRequest(Scanner scanner);
    boolean canProcessInitRequest(Scanner scanner);
    boolean canProcessRequest(ScannerType scannerType);
    void saveScanner(ScannerModel scannerModel) throws Exception;
}
