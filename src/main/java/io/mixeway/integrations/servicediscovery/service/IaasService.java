package io.mixeway.integrations.servicediscovery.service;

import io.mixeway.db.entity.IaasApi;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.*;
import io.mixeway.integrations.servicediscovery.plugin.IaasApiClient;
import io.mixeway.integrations.servicediscovery.plugin.openstack.apiclient.OpenStackApiClient;
import io.mixeway.rest.project.model.IaasApiPutModel;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.List;

/**
 * @author gsiewruk
 *
 * Service which handle operations with IAAS Platform REST APIs
 */
@Service
public class IaasService {

    private static final Logger log = LoggerFactory.getLogger(IaasService.class);
    private IaasApiRepository iaasApiRepository;
    private List<IaasApiClient> iaasApiClients;

    IaasService(IaasApiRepository iaasApiRepository, AssetRepository assetRepository, InterfaceRepository interfaceRepository,
                OpenStackApiClient apiClient, SecurityGroupRepository securityGroupRepository, List<IaasApiClient> iaasApiClients,
                SecurityGroupRuleRepository securityGroupRuleRepository, ActivityRepository activityRepository, RoutingDomainRepository routingDomainRepository){
        this.iaasApiRepository = iaasApiRepository;
        this.iaasApiClients = iaasApiClients;
    }

    /**
     * Loading data of VM and IP Addresses from API Clients
     */
    public void loadDataFromIaas(){
        List<IaasApi> iaasApis = iaasApiRepository.findByStatusAndEnabled(true, true);
        for (IaasApi iaasApi : iaasApis){
            for (IaasApiClient iaasApiClient : iaasApiClients){
                if (iaasApiClient.canProcessRequest(iaasApi)){
                    iaasApiClient.synchronize(iaasApi);
                }
            }
        }
    }

    /**
     * Testing if given configuration is properly saved, in particular if auth data are ok
     *
     * @param iaasApi
     * @throws CertificateException
     * @throws ParseException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws JSONException
     * @throws KeyStoreException
     * @throws KeyManagementException
     */
    public void testApi(IaasApi iaasApi) throws CertificateException, ParseException, NoSuchAlgorithmException, IOException, JSONException, KeyStoreException, KeyManagementException {
        for (IaasApiClient iaasApiClient : iaasApiClients){
            if (iaasApiClient.canProcessRequest(iaasApi)){
                iaasApiClient.testApiClient(iaasApi);
            }
        }
    }

    /**
     * Saving Model from GUI into DB for proper client
     *
     * @param iaasApiPutModel
     */
    public void saveApi(IaasApiPutModel iaasApiPutModel, Project project){
        for (IaasApiClient iaasApiClient : iaasApiClients){
            if (iaasApiClient.canProcessRequest(iaasApiPutModel)){
                iaasApiClient.saveApi(iaasApiPutModel, project);
            }
        }
    }
}
