package io.mixeway.plugins.codescan.service;

import io.mixeway.db.entity.CodeGroup;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.CodeVuln;
import io.mixeway.db.entity.Scanner;
import io.mixeway.rest.project.model.SASTProject;
import org.codehaus.jettison.json.JSONException;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.List;

public interface CodeScanClient {
    void loadVulnerabilities(Scanner scanner, CodeGroup codeGroup, String urlToGetNext, Boolean single, CodeProject codeProject, List<CodeVuln> codeVulns) throws ParseException, JSONException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException;
    Boolean runScan(CodeGroup cg,CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JSONException, ParseException;
    boolean isScanDone(CodeGroup cg) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, ParseException, JSONException;
    boolean canProcessRequest(CodeGroup cg);
    boolean canProcessRequest(Scanner scanner);
    List<SASTProject> getProjects(Scanner scanner) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException;
    boolean createProject(Scanner scanner, CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException;


    }
