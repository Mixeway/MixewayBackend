package io.mixeway.servicediscovery.plugin;

import io.mixeway.api.project.model.IaasApiPutModel;
import io.mixeway.db.entity.IaasApi;
import io.mixeway.db.entity.Project;
import org.codehaus.jettison.json.JSONException;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.text.ParseException;

/**
 * @author gsiewruk
 */
public interface IaasApiClient {
    void testApiClient(IaasApi iaasApi) throws CertificateException, ParseException, NoSuchAlgorithmException, IOException, JSONException, KeyStoreException, KeyManagementException;
    boolean canProcessRequest(IaasApi iaasApi);
    void synchronize(IaasApi iaasApi);
    void saveApi(IaasApiPutModel iaasApiPutModel, Project project);
    boolean canProcessRequest(IaasApiPutModel iaasApiPutModel);
}
