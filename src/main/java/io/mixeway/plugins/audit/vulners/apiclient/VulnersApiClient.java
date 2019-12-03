package io.mixeway.plugins.audit.vulners.apiclient;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Proxy.Type;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Iterator;
import java.util.Optional;

import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.SoftwarePacket;
import io.mixeway.db.entity.SoftwarePacketVulnerability;
import io.mixeway.db.repository.AssetRepository;
import io.mixeway.db.repository.SoftwarePacketRepository;
import io.mixeway.db.repository.SoftwarePacketVulnerabilityRepository;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

import com.google.gson.Gson;

import io.mixeway.plugins.audit.vulners.model.VulnersRequest;

@Component
public class VulnersApiClient {
	@Autowired
    AssetRepository assetRepository;
	@Autowired
    SoftwarePacketRepository softwarePacketRepository;
	@Autowired
    SoftwarePacketVulnerabilityRepository softwarePacketVulnerabilityRepository;


	private DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
	final static Logger log = LoggerFactory.getLogger(VulnersApiClient.class);
	public void handleVulnerRequest(VulnersRequest vulnReq, Asset asset) throws JSONException {
		RestTemplate restTemplate;
		restTemplate = restTemplate();
		HttpHeaders headers = new HttpHeaders();
		headers.set("Content-Type", "application/json");
		HttpEntity<String> entity = new HttpEntity<>(new Gson().toJson(vulnReq),headers);
		HttpEntity<String> response = restTemplate.exchange("https://vulners.com/api/v3/audit/audit/", HttpMethod.POST, entity, String.class);
		String result= response.getBody();
		JSONObject packages = new JSONObject(result).getJSONObject("data").getJSONObject("packages");
		Iterator<String> packageNames = packages.keys();
		while (packageNames.hasNext()) {
			String name = packageNames.next();
			if (packages.getJSONObject(name) != null) {
				Iterator<String> vulns = packages.getJSONObject(name).keys();
				String vulnCode;
				Double cvss =null;
				String fix = null;
				Optional<SoftwarePacket> softPack = softwarePacketRepository.findByName(name);
				softPack.ifPresent(this::deleteOldVulns);
				while (vulns.hasNext()) {
					vulnCode = vulns.next();
					JSONArray vulnArray = packages.getJSONObject(name).getJSONArray(vulnCode);
					if (vulnArray.length()>0) {
						cvss = vulnArray.getJSONObject(0).getJSONObject("cvss").getDouble("score"); 
						fix = vulnArray.getJSONObject(0).getString("fix"); 
						
					}
					createVulnerability(softPack.get(), vulnCode, cvss,fix,asset);
				}
			}
		}
		
	}
	// TO REVIEW
	private void createVulnerability(SoftwarePacket softPack, String vulnCode, Double cvss,String fix,Asset asset) {
		SoftwarePacketVulnerability spv = new SoftwarePacketVulnerability();
		spv.setName(vulnCode);
		spv.setScore(cvss);
		spv.setInserted(dateFormat.format(new Date()));
		spv.setSoftwarepacket(softPack);
		spv.setProject(asset.getProject());
		spv.setFix(fix);
		softwarePacketVulnerabilityRepository.save(spv);
		
	}
	@Transactional(propagation = Propagation.REQUIRED, readOnly = false)
	public void deleteOldVulns(SoftwarePacket softPack) {
		//for(SoftwarePacketVulnerability spv : softPack.getVulns()) {
		//	softwarePacketVulnerabilityRepository.delete(spv);
		//}
		//Long deleted = (long) 0;
		//softPack.getVulns().clear();
		softwarePacketVulnerabilityRepository.deleteVulnsForPacket(softPack.getId());
	}
	public RestTemplate restTemplate() {
	    SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();

	    Proxy proxy = new Proxy(Type.HTTP, new InetSocketAddress("126.204.4.20", 3128));
	    requestFactory.setProxy(proxy);

	    return new RestTemplate(requestFactory);
	}

}
