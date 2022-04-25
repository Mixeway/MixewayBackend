package io.mixeway.servicediscovery.plugin.openstack.apiclient;


import io.mixeway.api.project.model.IaasApiPutModel;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.servicediscovery.plugin.IaasApiClient;
import io.mixeway.utils.SecureRestTemplate;
import io.mixeway.utils.VaultHelper;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.orm.jpa.JpaObjectRetrievalFailureException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * @author gsiewruk
 * Api Client for OpenStack API
 */
@Component
public class OpenStackApiClient implements IaasApiClient {
	private static final String ORIGIN_API = "api";
	private static final String FE_NETWORK_TAG = "fe";
	private static final String ANY ="Any";
	private final static Logger log = LoggerFactory.getLogger(OpenStackApiClient.class);
	private SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
	private IaasApiRepository iaasApiRepository;
	private VaultHelper vaultHelper;
	private SecureRestTemplate secureRestTemplate;
	private AssetRepository assetRepository;
	private InterfaceRepository interfaceRepository;
	private SecurityGroupRepository securityGroupRepository;
	private SecurityGroupRuleRepository securityGroupRuleRepository;
	private ActivityRepository activityRepository;
	private RoutingDomainRepository routingDomainRepository;
	private IaasApiTypeRepisotory iaasApiTypeRepisotory;

	OpenStackApiClient(IaasApiRepository iaasApiRepository, VaultHelper vaultHelper, SecureRestTemplate secureRestTemplate,
					   AssetRepository assetRepository, InterfaceRepository interfaceRepository,
					   SecurityGroupRepository securityGroupRepository, IaasApiTypeRepisotory iaasApiTypeRepisotory,
					   SecurityGroupRuleRepository securityGroupRuleRepository, ActivityRepository activityRepository, RoutingDomainRepository routingDomainRepository){
		this.vaultHelper = vaultHelper;
		this.iaasApiTypeRepisotory = iaasApiTypeRepisotory;
		this.secureRestTemplate = secureRestTemplate;
		this.iaasApiRepository = iaasApiRepository;
		this.assetRepository = assetRepository;
		this.interfaceRepository = interfaceRepository;
		this.securityGroupRepository = securityGroupRepository;
		this.activityRepository = activityRepository;
		this.routingDomainRepository = routingDomainRepository;
		this.securityGroupRuleRepository = securityGroupRuleRepository;
	}
	
	private String buildJsonPostAuth(IaasApi api) throws JSONException {
		JSONArray ar = new JSONArray();
		ar.put("password");
		String jsonString = new JSONObject()
                .put("auth", new JSONObject()
                     .put("identity", new JSONObject()
                    		 .put("methods", ar)
                    		 .put("password", new JSONObject().
                    				 put("user", new JSONObject().
                    						 put("name", api.getUsername()).
                    						 put("password", vaultHelper.getPassword(api.getPassword())).
                    						 put("domain", new JSONObject().
                    								 put("name", api.getDomain()))))).
                     put("scope",new JSONObject().put("project", new JSONObject().put("id",api.getTenantId())))).toString();
		log.info("Creating json auth message for project: "+api.getTenantId());
		return jsonString;
	}
	
	private String sendAuthRequest(IaasApi api) throws JSONException, ParseException, IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
		Date datenow = sdf.parse(sdf.format(new Date()));
		boolean newTokenNeed;
		if(api.getTokenExpires() == null)
			newTokenNeed = true;
		else 
			newTokenNeed = !sdf.parse(api.getTokenExpires()).after(datenow);

		if (newTokenNeed) {
			RestTemplate restTemplate = secureRestTemplate.restTemplateForIaasApi(api);
			HttpHeaders headers = new HttpHeaders();
			headers.set("User-Agent", "");
			headers.set("Content-Type", "application/json");
			HttpEntity<String> entity = new HttpEntity<>(buildJsonPostAuth(api).trim().replaceAll("\\s+","").trim(),headers);
			HttpEntity<String> response = restTemplate.exchange(api.getIamUrl() + "/v3/auth/tokens", HttpMethod.POST, entity, String.class);
			HttpHeaders headersResponse = response.getHeaders();
			
			String token = Objects.requireNonNull(headersResponse.get("X-Subject-Token")).toString();
			api.setToken(token.substring(1, token.length() - 1));
			api.setTokenExpires(datenow.toInstant().plus(Duration.ofHours(9)).toString().replace("T", " ").replaceAll("Z", ""));
			api.setStatus(true);
			iaasApiRepository.save(api);
			log.info("Obtained x-auth-token for project: {} with expirationdate of {}",api.getTenantId(), api.getTokenExpires());
			return api.getToken();
		} else {
			api.setStatus(true);
			iaasApiRepository.save(api);
			return api.getToken();
		}
	}
	
	private JSONArray getServerInfo(IaasApi api) throws JSONException, ParseException {
		try {
			RestTemplate restTemplate;
			if (api.getExternal()) {
				SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
				Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("126.204.4.20", 3128));
				requestFactory.setProxy(proxy);
				restTemplate = new RestTemplate(requestFactory);
			} else
				restTemplate = new RestTemplate();

			HttpEntity<String> response = restTemplate.exchange(api.getServiceUrl() + "/v2/" + api.getTenantId() + "/servers",
					HttpMethod.GET, prepareHeadersForOpenStackRequests(api), String.class);
			String result = response.getBody();
			JSONObject responseJson = new JSONObject(result);
			return responseJson.getJSONArray("servers");
		}catch (ResourceAccessException | CertificateException | NoSuchAlgorithmException | KeyStoreException | KeyManagementException | IOException rae){
			log.error("OpenStack synchro - get server info error occured: {}", rae.getLocalizedMessage());
		}
		return null;
	}
	private JSONObject getServerDetails(IaasApi api, Asset asset) throws JSONException, ParseException, IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
		RestTemplate restTemplate = secureRestTemplate.restTemplateForIaasApi(api);
		HttpEntity<String> response = restTemplate.exchange(api.getServiceUrl()+"/v2/"+api.getTenantId()+"/servers/"+asset.getAssetId(),
				HttpMethod.GET, prepareHeadersForOpenStackRequests(api), String.class);
		String result= response.getBody();
		JSONObject responseJson = new JSONObject(result);
		return responseJson.getJSONObject("server");
	}
	private JSONArray getFloatingIps (IaasApi api) throws JSONException, ParseException, IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
		RestTemplate restTemplate = secureRestTemplate.restTemplateForIaasApi(api);
		try {
			HttpEntity<String> response = restTemplate.exchange(api.getServiceUrl()+"/v2/"+api.getTenantId()+"/os-floating-ips",
					HttpMethod.GET, prepareHeadersForOpenStackRequests(api), String.class);
			String result= response.getBody();
			JSONObject responseJson = new JSONObject(result);
			return responseJson.getJSONArray("floating_ips");
		} catch (ResourceAccessException rac) {
			return new JSONArray();
		}
	}
	private JSONArray getInterfaces(IaasApi api, Asset asset) throws JSONException, ParseException {
		try {
			RestTemplate restTemplate = secureRestTemplate.restTemplateForIaasApi(api);
			HttpEntity<String> response = restTemplate.exchange(api.getServiceUrl() + "/v2/" + api.getTenantId() + "/servers/" + asset.getAssetId() + "/os-interface",
					HttpMethod.GET, prepareHeadersForOpenStackRequests(api), String.class);
			String result = response.getBody();
			JSONObject responseJson = new JSONObject(result);
			return responseJson.getJSONArray("interfaceAttachments");
		} catch (ResourceAccessException rae){
			log.error("ResourceAccessException during getInterface for {}",asset.getProject().getName());
		} catch (IOException | NoSuchAlgorithmException | KeyStoreException | CertificateException | KeyManagementException e) {
			log.warn("Exception {} came up durring getting interfaces for {}", e.getLocalizedMessage(),asset.getName());
		}
		return null;
	}
	private JSONArray getSecurityGroups(IaasApi api, Asset asset) {
		try {
			RestTemplate restTemplate = secureRestTemplate.restTemplateForIaasApi(api);

			HttpEntity<String> response = restTemplate.exchange(api.getServiceUrl() + "/v2/" + api.getTenantId() + "/servers/" + asset.getAssetId() + "/os-security-groups",
					HttpMethod.GET, prepareHeadersForOpenStackRequests(api), String.class);
			String result = response.getBody();
			JSONObject responseJson = new JSONObject(result);
			return responseJson.getJSONArray("security_groups");
		} catch (Exception rae){
			log.error("ResourceAccessException during getInterface for {}",asset.getProject().getName());
		}
		return null;
	}

	private HttpEntity<String> prepareHeadersForOpenStackRequests(IaasApi api) throws JSONException, ParseException, UnknownHostException,
			CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException{
		HttpHeaders headers = new HttpHeaders();
		headers.set("User-Agent", "");
		headers.set("X-Auth-Token", sendAuthRequest(api));
		return new HttpEntity<>(headers);
	}

	@Override
	public void testApiClient(IaasApi iaasApi) throws CertificateException, ParseException, NoSuchAlgorithmException, IOException, JSONException, KeyStoreException, KeyManagementException {
		this.sendAuthRequest(iaasApi);
	}

	@Override
	public boolean canProcessRequest(IaasApi iaasApi) {
		return iaasApi.getIaasApiType().getName().equals(Constants.IAAS_API_TYPE_OPENSTACK) && iaasApi.getStatus() && iaasApi.getEnabled();
	}

	@Override
	@Transactional
	public void synchronize(IaasApi api) {
		deactivateAssets(api);
		deactivateInterfaces(api);
		//Pobranie listy floting ip = publiczne interfejsy
		try {
			JSONArray floatingIps = this.getFloatingIps(api);
			createOrUpdateAssetsWithPublicIp(api,floatingIps);
			// Robienie nowych serwerow ECS
			int newServers = 0;
			JSONArray serverList = this.getServerInfo(api);
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
		} catch(NullPointerException | JSONException | ParseException | IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
			log.error("OpenStack synchro - nullpointer due to previous error");
		}
	}

	@Override
	public void saveApi(IaasApiPutModel iaasApiPutModel, Project project) {
		IaasApi iaasApi = new IaasApi();
		iaasApi.setIamUrl(iaasApiPutModel.getIamApi());
		iaasApi.setServiceUrl(iaasApiPutModel.getServiceApi());
		iaasApi.setNetworkUrl(iaasApiPutModel.getNetworkApi());
		iaasApi.setTenantId(iaasApiPutModel.getProjectid());
		iaasApi.setUsername(iaasApiPutModel.getUsername());
		iaasApi.setRoutingDomain(routingDomainRepository.getOne(iaasApiPutModel.getRoutingDomainForIaasApi()));
		iaasApi.setProject(project);
		iaasApi.setEnabled(false);
		iaasApi.setStatus(false);
		iaasApi.setExternal(false);
		iaasApi.setIaasApiType(iaasApiTypeRepisotory.findByName(Constants.IAAS_API_TYPE_OPENSTACK));
		iaasApiRepository.save(iaasApi);
		String uuidToken = UUID.randomUUID().toString();
		if (vaultHelper.savePassword(iaasApiPutModel.getPassword(), uuidToken)){
			iaasApi.setPassword(uuidToken);
		} else {
			iaasApi.setPassword(iaasApiPutModel.getPassword());
		}
		iaasApiRepository.save(iaasApi);
	}

	@Override
	public boolean canProcessRequest(IaasApiPutModel iaasApiPutModel) {
		return iaasApiPutModel.getApiType().equals(Constants.IAAS_API_TYPE_OPENSTACK);
	}

	private void createOrUpdateAssetsWithPublicIp(IaasApi api, JSONArray jsonArray) throws JSONException {
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
			JSONArray groups = this.getSecurityGroups(api, asset);
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

	private void deactivateAssets(IaasApi api) {

		List<Asset> assets = assetRepository.findByProjectId(api.getProject().getId());
		for (Asset asset : assets) {
			asset.setActive(false);
			assetRepository.save(asset);
		}
	}
	private void deactivateInterfaces(IaasApi api) {
		List<Interface> intfs= interfaceRepository.findByAssetIn(new ArrayList<>(api.getProject().getAssets()));
		for (Interface intf : intfs) {
			intf.setActive(false);
			interfaceRepository.save(intf);
		}
	}
	public void loadInterfaces(IaasApi api, Asset asset, JSONArray floatingIps) throws JSONException, ParseException, UnknownHostException {
		try{
			JSONArray interfaces = this.getInterfaces(api, asset);
			for (int i = 0; i < interfaces.length(); i++) {
				String state = interfaces.getJSONObject(i).getString("port_state");
				String macAddr = interfaces.getJSONObject(i).getString("mac_addr");
				Interface intf = interfaceRepository.findByMacaddr(macAddr);
				if (intf == null)
					intf = new Interface();
				intf.setActive(state.equals("ACTIVE"));
				intf.setAutoCreated(false);
				intf.setAsset(asset);
				intf.setRoutingDomain(asset.getRoutingDomain());
				intf.setMacaddr(macAddr);
				intf.setPrivateip(interfaces.getJSONObject(i).getJSONArray("fixed_ips").getJSONObject(0).getString("ip_address"));
				intf.setSubnetId(interfaces.getJSONObject(i).getJSONArray("fixed_ips").getJSONObject(0).getString("subnet_id"));
				intf.setFloatingip(findFloatingIp(floatingIps, intf.getPrivateip()));
				intf.setNetworkTag(FE_NETWORK_TAG);
				interfaceRepository.save(intf);
			}
		} catch (NullPointerException npe){
			log.warn("OpenStack LoadInterfaces NullPointerException occured...");
		}
	}
	private String findFloatingIp(JSONArray flatingIps, String fixedIp) throws JSONException {
		for (int i = 0; i < flatingIps.length(); i++) {
			String fip = flatingIps.getJSONObject(i).getString("fixed_ip");
			if (fip != null)
				if (flatingIps.getJSONObject(i).getString("fixed_ip").equals(fixedIp))
					return flatingIps.getJSONObject(i).getString("ip");

		}
		return null;
	}
}
