package io.mixeway.plugins.audit.vulners.controller;

import io.mixeway.plugins.audit.vulners.model.Packets;
import io.mixeway.plugins.audit.vulners.service.VulnersService;
import io.mixeway.pojo.Status;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.transaction.Transactional;

@Controller
public class VulnersApiDiscoveryController {

    @Autowired
    VulnersService vulnersService;

    @Transactional
    @PreAuthorize("permitAll()")
    @RequestMapping(method = RequestMethod.POST, value = "/api/packetdiscovery")
    public ResponseEntity<Status> packetDiscovery(@RequestBody Packets packets){

        return vulnersService.savePacketDiscovery(packets);

    }

}
