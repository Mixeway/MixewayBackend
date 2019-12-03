package io.mixeway.plugins.servicediscovery.openstack.apiclient;


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
import java.util.Date;
import java.util.Map;
import java.util.Objects;

import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.IaasApi;
import io.mixeway.db.repository.IaasApiRepository;
import io.mixeway.pojo.SecureRestTemplate;
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
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.VaultResponseSupport;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

@Component
public class OpenStackApiClient {

    private final static Logger log = LoggerFactory.getLogger(OpenStackApiClient.class);
	private SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private IaasApiRepository iaasApiRepository;
	private VaultOperations operations;
	private SecureRestTemplate secureRestTemplate;

	@Autowired
	OpenStackApiClient(IaasApiRepository iaasApiRepository, VaultOperations operations, SecureRestTemplate secureRestTemplate){
		this.operations = operations;
		this.secureRestTemplate = secureRestTemplate;
		this.iaasApiRepository = iaasApiRepository;
	}
	
	private String buildJsonPostAuth(IaasApi api) throws JSONException {
		VaultResponseSupport<Map<String,Object>> response = operations.read("secret/"+api.getPassword());
		JSONArray ar = new JSONArray();
		ar.put("password");
		assert response != null;
		String jsonString = new JSONObject()
                .put("auth", new JSONObject()
                     .put("identity", new JSONObject()
                    		 .put("methods", ar)
                    		 .put("password", new JSONObject().
                    				 put("user", new JSONObject().
                    						 put("name", api.getUsername()).
                    						 put("password", Objects.requireNonNull(response.getData()).get("password")).
                    						 put("domain", new JSONObject().
                    								 put("name", api.getDomain()))))).
                     put("scope",new JSONObject().put("project", new JSONObject().put("id",api.getTenantId())))).toString();
		log.info("Creating json auth message for project: "+api.getTenantId());
		return jsonString;
	}
	
	public String sendAuthRequest(IaasApi api) throws JSONException, ParseException, IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
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
	
	public JSONArray getServerInfo(IaasApi api) throws JSONException, ParseException {
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
	public JSONObject getServerDetails(IaasApi api, Asset asset) throws JSONException, ParseException, IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
		RestTemplate restTemplate = secureRestTemplate.restTemplateForIaasApi(api);
		HttpEntity<String> response = restTemplate.exchange(api.getServiceUrl()+"/v2/"+api.getTenantId()+"/servers/"+asset.getAssetId(),
				HttpMethod.GET, prepareHeadersForOpenStackRequests(api), String.class);
		String result= response.getBody();
		JSONObject responseJson = new JSONObject(result);
		return responseJson.getJSONObject("server");
	}
	public JSONArray getFloatingIps (IaasApi api) throws JSONException, ParseException, IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
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
	public JSONArray getInterfaces(IaasApi api, Asset asset) throws JSONException, ParseException {
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
			e.printStackTrace();
		}
		return null;
	}
	public JSONArray getSecurityGroups(IaasApi api, Asset asset) {
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

}
