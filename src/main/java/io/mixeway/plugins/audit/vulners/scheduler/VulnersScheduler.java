package io.mixeway.plugins.audit.vulners.scheduler;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;


import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.SoftwarePacket;
import io.mixeway.db.entity.SoftwarePacketVulnerability;
import io.mixeway.db.repository.AssetRepository;
import io.mixeway.db.repository.SoftwarePacketRepository;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import io.mixeway.plugins.audit.vulners.apiclient.VulnersApiClient;
import io.mixeway.plugins.audit.vulners.model.VulnersRequest;

@Component
@Transactional
public class VulnersScheduler {
    private final AssetRepository assetRepository;
	private final VulnersApiClient apiClient;
    private final SoftwarePacketRepository softwarePacketRepository;
	private static final Logger log = LoggerFactory.getLogger(VulnersScheduler.class);

	VulnersScheduler(final AssetRepository assetRepository, final VulnersApiClient vulnersApiClient, final SoftwarePacketRepository softwarePacketRepository) {
		this.softwarePacketRepository = softwarePacketRepository;
		this.apiClient = vulnersApiClient;
		this.assetRepository = assetRepository;
	}
	
	//Every 24h
	//@Scheduled(fixedDelay = 86400000 )
    public void getVulners() throws JSONException, ParseException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, FileNotFoundException, IOException {

    	List<Integer> assetIds = assetRepository.getAssetIdWithPackets();
    	log.info("Vulners - disabling software packets");
    	deactivateSoftwarePackets();
    	for (int id : assetIds) {
    		Asset asset = assetRepository.getOne((long)id);
    		log.info("Vulners - loading vulns for packets inside {} ",asset.getName());
    		VulnersRequest vulnReq = prepareVulnerRequestForAsset(asset);
    		apiClient.handleVulnerRequest(vulnReq, asset);
    	}
    }
	@Transactional(propagation = Propagation.REQUIRED, readOnly = false)
	public void deactivateSoftwarePackets() {
		for (SoftwarePacket sp :softwarePacketRepository.findAll()) {
			sp.setUptated(false);
			softwarePacketRepository.save(sp);
		}
		
	}
	private VulnersRequest prepareVulnerRequestForAsset(Asset asset) {
		VulnersRequest req = new VulnersRequest();
		req.setOs(asset.getOs().split(" ")[0]);
		req.setVersion(Double.parseDouble(asset.getOsversion()));
		List<String> packets = new ArrayList<>();
		for (SoftwarePacket sp : asset.getSoftwarePackets()) {
			if (!sp.getUptated()) {
				packets.add(sp.getName());
				sp.setUptated(true);
				softwarePacketRepository.save(sp);
			}
		}
		req.setPacket(packets);
		return req;
	}

}
