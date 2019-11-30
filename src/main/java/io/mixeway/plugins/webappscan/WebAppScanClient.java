package io.mixeway.plugins.webappscan;

import io.mixeway.db.entity.Scanner;
import io.mixeway.db.entity.WebApp;
import io.mixeway.db.entity.WebAppVuln;

import java.util.List;

public interface WebAppScanClient {
    void runScan(WebApp webApp, Scanner scanner) throws Exception;
    void configureWebApp(WebApp webApp, Scanner scanner) throws Exception;
    Boolean isScanDone(Scanner scanner, WebApp webApp) throws Exception;
    Boolean loadVulnerabilities(Scanner scanner, WebApp webApp, String paginator, List<WebAppVuln> oldVulns) throws Exception;
    boolean canProcessRequest(Scanner scanner);

}
