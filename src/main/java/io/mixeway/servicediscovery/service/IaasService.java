package io.mixeway.servicediscovery.service;

import io.mixeway.api.project.model.IaasApiPutModel;
import io.mixeway.db.entity.IaasApi;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.*;
import io.mixeway.servicediscovery.plugin.IaasApiClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.codehaus.jettison.json.JSONException;
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
@Log4j2
@RequiredArgsConstructor
public class IaasService {

    private final IaasApiRepository iaasApiRepository;
    private final List<IaasApiClient> iaasApiClients;

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
