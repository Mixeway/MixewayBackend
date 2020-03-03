package io.mixeway.plugins.infrastructurescan.controller;

import io.mixeway.plugins.infrastructurescan.model.NetworkScanRequestModel;
import io.mixeway.pojo.Status;
import org.codehaus.jettison.json.JSONException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import io.mixeway.plugins.infrastructurescan.service.NetworkScanService;

import javax.xml.bind.JAXBException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

@Controller
public class NetworkScanApiController {

    private final NetworkScanService networkScanService;
    @Autowired
    NetworkScanApiController(NetworkScanService networkScanService){
        this.networkScanService = networkScanService;
    }

    @PreAuthorize("hasAuthority('ROLE_API')")
    @RequestMapping(value = "/api/koordynator/network",method = RequestMethod.POST)
    public ResponseEntity<Status> createAndRunNetworkscan(@RequestBody NetworkScanRequestModel req) throws Exception {
        return networkScanService.createAndRunNetworkScan(req);
    }
    @PreAuthorize("hasAuthority('ROLE_API')")
    @RequestMapping(value = "/api/koordynator/network/check/{ciid}",method = RequestMethod.GET)
    public ResponseEntity<Status> checkNetworkScanTest(@PathVariable("ciid") String ciid) {
        return networkScanService.checkScanStatusForCiid(ciid);
    }

}
