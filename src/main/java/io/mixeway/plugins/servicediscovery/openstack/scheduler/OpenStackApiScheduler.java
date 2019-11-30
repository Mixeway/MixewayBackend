package io.mixeway.plugins.servicediscovery.openstack.scheduler;

import java.io.IOException;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.plugins.servicediscovery.openstack.apiclient.OpenStackApiClient;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.orm.jpa.JpaObjectRetrievalFailureException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.vault.core.VaultOperations;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;

@Component
public class OpenStackApiScheduler {
	private static final String ORIGIN_API = "api";
	private static final String FE_NETWORK_TAG = "fe";
	private static final String ANY ="Any";
    private static final Logger log = LoggerFactory.getLogger(OpenStackApiScheduler.class);
    @Autowired
    IaasApiRepository iaasApiRepository;
    @Autowired
    AssetRepository assetRepository;
    @Autowired
    InterfaceRepository interfaceRepository;
  
    @Autowired
    OpenStackApiClient apiClient;
    
    @Autowired
    SecurityGroupRepository securityGroupRepository;
    @Autowired
    SecurityGroupRuleRepository securityGroupRuleRepository;
    
    @Autowired
    VaultOperations operations;
    @Autowired
    ActivityRepository activityRepository;
    @Autowired
	RoutingDomainRepository routingDomainRepository;
    
    
    //Every 5min
	@Transactional
    @Scheduled(fixedDelay = 300000)
    public void reportCurrentTime() throws JSONException, ParseException, UnknownHostException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException {
    	List<IaasApi> apis = iaasApiRepository.findAll();
    	for (IaasApi api : apis) {
    		if(api.getEnabled()) {
	    		//deaktywacja assetu
	    		deactivateAssets(api);
	    		deactivateInterfaces(api);
	    		//Pobranie listy floting ip = publiczne interfejsy
	    		try {
		    		JSONArray floatingIps = apiClient.getFloatingIps(api);
		    		createOrUpdateAssetsWithPublicIp(api,floatingIps);
		    		// Robienie nowych serwerow ECS
		    		int newServers = 0;
		    		JSONArray serverList = apiClient.getServerInfo(api);
		    		for (int i = 0; i < serverList.length(); i++) {
		    			String assetName = serverList.getJSONObject(i).get("name").toString();
		    			String assetId = serverList.getJSONObject(i).get("id").toString();
		    			Asset asset = assetRepository.findByAssetId(assetId);
		    			if (asset == null) {
		    				asset = new Asset();
		    				asset.setAssetType(Constants.ASSET_IP_SINGLE);
		    				asset.setAssetId(assetId);
		    				asset.setActive(true);
		    				asset.setRoutingDomain(api.getRoutingDomain());
		    				asset.setName(assetName);
		    				asset.setProject(api.getProject());
		    				asset.setOrigin(ORIGIN_API);
		    				assetRepository.save(asset);
		    				newServers++;
		    			}
		    			asset.setActive(true);
		    			assetRepository.save(asset);
		    			
		    			//load Interfaces for asset
		    			//loadInterfaces(api, asset, floatingIps);
		    			
		    			// Load security groups informations
		    			//loadSecurityGroups(api,asset);
		    		}
		    		if (newServers > 0 ) {
		    			Activity act = new Activity();
		    	        act.setInserted(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
		    	        act.setName("Created: "+newServers+" new servers for project: "+api.getProject().getName());
		    	        activityRepository.save(act);
		    		}
		    		if (newServers > 0)
		    			log.info("Saved: {} new assets for project: {}", newServers, api.getTenantId());
	    		} catch(HttpClientErrorException e) {
	    			log.error("Error occured during synchronization msg is '{}' for project: '{}'",e.getMessage(), api.getProject().getName());
	    		} catch(NullPointerException e) {
					log.error("OpenStack synchro - nullpointer due to previous error");
				}
	    	}
    	}
    }
    @Transactional
    public void createOrUpdateAssetsWithPublicIp(IaasApi api, JSONArray jsonArray) throws JSONException {
			RoutingDomain routingDomain = routingDomainRepository.findByName(Constants.DOMAIN_INTERNET);
			assetRepository.disactivateAssetByRoutingDomain(routingDomain.getId());
			for (int i = 0; i < jsonArray.length(); i++) {
				Optional<Interface> intf = interfaceRepository.findByAssetInAndPrivateip(api.getProject().getAssets(), jsonArray.getJSONObject(i).getString("ip"));
				if (intf.isPresent()) {
					intf.get().setActive(true);
				} else {
					Asset asset = new Asset();
					asset.setName(jsonArray.getJSONObject(i).getString("ip"));
					asset.setOrigin("auto");
					asset.setActive(true);
					asset.setRoutingDomain(routingDomain);
					asset.setProject(api.getProject());
					asset = assetRepository.save(asset);
					Interface intfnew = new Interface();
					intfnew.setActive(true);
					intfnew.setPrivateip(jsonArray.getJSONObject(i).getString("ip"));
					intfnew.setRoutingDomain(routingDomain);
					intfnew.setAsset(asset);
					intfnew.setAutoCreated(false);
					interfaceRepository.save(intfnew);
					log.info("Created asset with IP {} for project {} with routing domain {}", intfnew.getPrivateip(), api.getProject().getName(), routingDomain.getName());
				}

			}
	}

	private void loadSecurityGroups(IaasApi api, Asset asset) throws ParseException, JSONException, UnknownHostException {
		try {
			JSONArray groups = apiClient.getSecurityGroups(api, asset);
			// Interacja po grupach w tablicy
			for (int i = 0; i < groups.length(); i++) {
				SecurityGroup securityGroup = securityGroupRepository.findBySecuritygroupid(groups.getJSONObject(i).getString("id"));
				if (securityGroup == null)
					securityGroup = new SecurityGroup();
				securityGroup.setName(groups.getJSONObject(i).getString("name"));
				securityGroup.setSecuritygroupid(groups.getJSONObject(i).getString("id"));
				if(securityGroup.getAssets() == null) {
					Set<Asset> assetSet = new HashSet<Asset>() {{
					    add(asset);
					}};
					securityGroup.setAssets(assetSet);
				}
				else
					securityGroup.getAssets().add(asset);
				securityGroup.getAssets().add(asset);
				securityGroupRepository.save(securityGroup);
				//Iteracja po regulach w grupach
				JSONArray rules = groups.getJSONObject(i).getJSONArray("rules");
				for(int k=0; k< rules.length(); k++) {
					try {
						SecurityGroupRule rule = securityGroupRuleRepository.findByRuleid(rules.getJSONObject(k).getString("id"));
						if (rule == null)
							rule = new SecurityGroupRule();
						rule.setSecuritygroup(securityGroup);
						rule.setDirection("Inbound");
						//PORTS
						if (rules.getJSONObject(k).getInt("from_port") == -1 && rules.getJSONObject(k).getInt("to_port") == -1 )
							rule.setPorts(ANY);
						else if ( rules.getJSONObject(k).getInt("from_port") == rules.getJSONObject(k).getInt("to_port"))
							rule.setPorts(rules.getJSONObject(k).getInt("from_port")+"");
						else
							rule.setPorts(rules.getJSONObject(k).getInt("from_port") +" - "+rules.getJSONObject(k).getInt("to_port"));
						//PROTOCOL
						if (rules.getJSONObject(k).getString("ip_protocol") == null)
							rule.setProtocol(ANY);
						else
							rule.setProtocol(rules.getJSONObject(k).getString("ip_protocol"));
						//DESTINATION
						if (rules.getJSONObject(k).getJSONObject("group").length() > 0)
							rule.setDestination(rules.getJSONObject(k).getJSONObject("group").getString("name"));
						else if (rules.getJSONObject(k).getJSONObject("ip_range").length() > 0 )
							rule.setDestination(rules.getJSONObject(k).getJSONObject("ip_range").getString("cidr"));
						else
							rule.setDestination(ANY);
						rule.setRuleid(rules.getJSONObject(k).getString("id"));
						securityGroupRuleRepository.save(rule);
					} catch (JSONException je) {
						// STUPID EXCEPTION
					}
				}
			
			}
		} catch (JpaObjectRetrievalFailureException e) {
			log.error("JpaObjectRetrievalFailureException Exception during securityGroup loading..");
		} catch (HttpServerErrorException ex) {
			log.error("Http 500 error during securityGroup loading..");
		} catch (NullPointerException npe) {
			log.error("OpenStack getSecurityGroup null pointer exception occured..");
		}

		
	}

	public void deactivateAssets(IaasApi api) {
		
    	List<Asset> assets = assetRepository.findByProjectId(api.getProject().getId());
    	for (Asset asset : assets) {
    		asset.setActive(false);
    		assetRepository.save(asset);
    	}
    }
	public void deactivateInterfaces(IaasApi api) {
    	List<Interface> intfs= interfaceRepository.findByAssetIn(new ArrayList<>(api.getProject().getAssets()));
    	for (Interface intf : intfs) {
    		intf.setActive(false);
    		interfaceRepository.save(intf);
    	}
    }
    public void loadInterfaces(IaasApi api, Asset asset, JSONArray floatingIps) throws JSONException, ParseException, UnknownHostException {
		try{
			JSONArray interfaces = apiClient.getInterfaces(api, asset);
			int newInterfaces = 0;
			for (int i = 0; i < interfaces.length(); i++) {
				String state = interfaces.getJSONObject(i).getString("port_state");
				String macAddr = interfaces.getJSONObject(i).getString("mac_addr");
				Interface intf = interfaceRepository.findByMacaddr(macAddr);
				if (intf == null)
					intf = new Interface();
				intf.setActive(state.equals("ACTIVE") ? true : false);
				intf.setAutoCreated(false);
				intf.setAsset(asset);
				intf.setRoutingDomain(asset.getRoutingDomain());
				intf.setMacaddr(macAddr);
				intf.setPrivateip(interfaces.getJSONObject(i).getJSONArray("fixed_ips").getJSONObject(0).getString("ip_address"));
				intf.setSubnetId(interfaces.getJSONObject(i).getJSONArray("fixed_ips").getJSONObject(0).getString("subnet_id"));
				intf.setFloatingip(findFloatingIp(floatingIps, intf.getPrivateip()));
				intf.setNetworkTag(FE_NETWORK_TAG);
				interfaceRepository.save(intf);
				newInterfaces++;
			}
		} catch (NullPointerException npe){
			log.warn("OpenStack LoadInterfaces NullPointerException occured...");
		}
    }
    public String findFloatingIp(JSONArray flatingIps, String fixedIp) throws JSONException {
    	for (int i = 0; i < flatingIps.length(); i++) {
    		String fip = flatingIps.getJSONObject(i).getString("fixed_ip");
    		if (fip != null)
	    		if (flatingIps.getJSONObject(i).getString("fixed_ip").equals(fixedIp))
	    			return flatingIps.getJSONObject(i).getString("ip");
    		
    	}
    	return null;
    }
    
    
}
