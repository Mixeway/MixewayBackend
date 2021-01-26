package io.mixeway.integrations.audit.plugins.vulners.apiclient;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Proxy.Type;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Iterator;
import java.util.Optional;

import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.db.entity.SoftwarePacket;
import io.mixeway.db.entity.Vulnerability;
import io.mixeway.db.repository.SoftwarePacketRepository;
import io.mixeway.domain.service.vulnerability.VulnTemplate;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

import com.google.gson.Gson;

import io.mixeway.integrations.audit.plugins.vulners.model.VulnersRequest;

@Component
public class VulnersApiClient {
    private final SoftwarePacketRepository softwarePacketRepository;
    private final VulnTemplate vulnTemplate;

	VulnersApiClient(final SoftwarePacketRepository softwarePacketRepository, VulnTemplate vulnTemplate
					 ){
		this.softwarePacketRepository = softwarePacketRepository;
		this.vulnTemplate = vulnTemplate;
	}


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
					if (softPack.isPresent()) {
						createVulnerability(softPack.get(), vulnCode, cvss, fix, asset);
					}
				}
			}
		}
		
	}
	// TO REVIEW
	private void createVulnerability(SoftwarePacket softPack, String vulnCode, Double cvss,String fix,Asset asset) {
		Vulnerability vulnerability = vulnTemplate.createOrGetVulnerabilityService.createOrGetVulnerability(vulnCode);
		ProjectVulnerability spv = new ProjectVulnerability(softPack,null,vulnerability,null, fix,createScore(cvss),null,null,null,vulnTemplate.SOURCE_OSPACKAGE, null);
		vulnTemplate.projectVulnerabilityRepository.save(spv);
		
	}
	private String createScore(Double severity) {
		if (severity >= 8){
			return "Critical";
		} else if (severity >= 6 && severity < 8){
			return "High";
		} else if (severity >= 4 && severity < 6){
			return "Medium";
		} else
			return "Low";
	}

	@Transactional(propagation = Propagation.REQUIRED, readOnly = false)
	public void deleteOldVulns(SoftwarePacket softPack) {
		vulnTemplate.projectVulnerabilityRepository.deleteBySoftwarePacket(softPack);
	}
	public RestTemplate restTemplate() {
	    SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();

	    Proxy proxy = new Proxy(Type.HTTP, new InetSocketAddress("126.204.4.20", 3128));
	    requestFactory.setProxy(proxy);

	    return new RestTemplate(requestFactory);
	}

}
