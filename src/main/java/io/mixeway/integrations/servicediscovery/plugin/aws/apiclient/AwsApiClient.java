package io.mixeway.integrations.servicediscovery.plugin.aws.apiclient;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.ec2.model.*;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.IaasApi;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.*;
import io.mixeway.integrations.servicediscovery.plugin.IaasApiClient;
import io.mixeway.pojo.VaultHelper;
import io.mixeway.rest.project.model.IaasApiPutModel;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import javax.validation.Valid;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Optional;
import java.util.UUID;

/**
 * @author gsiewruk
 *
 * Class which represent plugin for AWS integration
 */
@Component
public class AwsApiClient implements IaasApiClient {

    @Value("${HTTPS_PROXY}")
    String httpsProxy;
    @Value("${NO_PROXY}")
    String nonProxyHosts;
    private static final Logger log = LoggerFactory.getLogger(AwsApiClient.class);
    private final IaasApiRepository iaasApiRepository;
    private final IaasApiTypeRepisotory iaasApiTypeRepisotory;
    private final VaultHelper vaultHelper;
    private final RoutingDomainRepository routingDomainRepository;
    private final InterfaceRepository interfaceRepository;
    private final AssetRepository assetRepository;

    public AwsApiClient(IaasApiRepository iaasApiRepository, IaasApiTypeRepisotory iaasApiTypeRepisotory,
                        VaultHelper vaultHelper, RoutingDomainRepository routingDomainRepository,
                        InterfaceRepository interfaceRepository, AssetRepository assetRepository){
        this.iaasApiRepository = iaasApiRepository;
        this.interfaceRepository = interfaceRepository;
        this.vaultHelper = vaultHelper;
        this.assetRepository = assetRepository;
        this.routingDomainRepository = routingDomainRepository;
        this.iaasApiTypeRepisotory = iaasApiTypeRepisotory;
    }

    /**
     * Method which test if given credentials is properly working in scope of AWS EC2 Integration
     *
     * @param iaasApi object to test credentials
     */
    @Override
    @Transactional
    public void testApiClient(IaasApi iaasApi) {
        AWSCredentials credentials = new BasicAWSCredentials(iaasApi.getUsername(),vaultHelper.getPassword(iaasApi.getPassword()));
        AmazonEC2 client = AmazonEC2ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(credentials))
                .withRegion(iaasApi.getRegion())
                .build();
        DescribeInstancesRequest request = new DescribeInstancesRequest();
        setProxy();
        DescribeInstancesResult response = client.describeInstances(request);
        iaasApi.setStatus(true);
        iaasApiRepository.save(iaasApi);
        unsetProxy();
    }

    private void setProxy() {
        try {
            URL proxy = new URL(httpsProxy);
            System.setProperty("https.proxyHost",proxy.getHost());
            System.setProperty("https.proxyPort", String.valueOf(proxy.getPort()));
            System.setProperty("http.proxyHost",proxy.getHost());
            System.setProperty("http.proxyPort", String.valueOf(proxy.getPort()));
            System.setProperty("https.nonProxyHosts", nonProxyHosts);
            System.setProperty("http.nonProxyHosts", nonProxyHosts);
        } catch (MalformedURLException e) {
            log.debug("Cannot set proxy {}",e.getLocalizedMessage());
        }
    }

    private void unsetProxy() {
        try {
            URL proxy = new URL(httpsProxy);
            System.setProperty("https.proxyHost","");
            System.setProperty("https.proxyPort","");
            System.setProperty("http.proxyHost","");
            System.setProperty("http.proxyPort","");
            System.setProperty("https.nonProxyHosts", "");
            System.setProperty("http.nonProxyHosts", "");
        } catch (MalformedURLException e) {
            log.debug("Cannot set proxy {}",e.getLocalizedMessage());
        }
    }

    /**
     *
     * Verification if fiven IaasApi Object can be processed via IaasApiType
     *
     * @param iaasApi object to verify
     * @return info if given ApiClient can process request
     */
    @Override
    public boolean canProcessRequest(IaasApi iaasApi) {
        return iaasApi.getIaasApiType().getName().equals(Constants.IAAS_API_TYPE_AWS_EC2);
    }

    /**
     * Sychronization. Method is taking all instances in given region which machest VPC-ID and later sotres them in DB
     *
     * @param iaasApi object with region and vpc-id
     */
    @Override
    @Transactional
    public void synchronize(IaasApi iaasApi) {
        AWSCredentials credentials = new BasicAWSCredentials(iaasApi.getUsername(),vaultHelper.getPassword(iaasApi.getPassword()));
        AmazonEC2 client = AmazonEC2ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(credentials))
                .withRegion(iaasApi.getRegion())
                .build();

        DescribeInstancesRequest req1 = new DescribeInstancesRequest()
                .withFilters(new Filter().withName(Constants.AWS_VPC_ID)
                        .withValues(iaasApi.getTenantId()));
        setProxy();
        DescribeInstancesResult response = client.describeInstances(req1);
        unsetProxy();
        for(Reservation reservation : response.getReservations()) {
            for (Instance instance : reservation.getInstances()) {
                createOrUpdateAssetPrivate(instance,iaasApi);
            }
        }
    }

    /**
     * Method which is processing Instance obtained by AWS Client and process it in order to create Assets and Interfaces
     *
     * @param instance received by API Call
     * @param iaasApi on which API Call were made
     */
    private void createOrUpdateAssetPrivate(Instance instance, IaasApi iaasApi) {
        int added = 0;
        String assetName = "";
        if (instance.getTags().stream().filter(p -> p.getKey().equals("Name")).findFirst().orElse(null).getValue() != null){
            assetName = instance.getTags().stream().filter(p -> p.getKey().equals("Name")).findFirst().orElse(null).getValue();
        } else {
            assetName = "empty - should not happen";
        }
        Optional<Asset> asset = assetRepository.findByNameAndProject(assetName, iaasApi.getProject());
        if (asset.isPresent()){
            Interface anInterface = asset.get().getInterfaces().stream().filter(i -> i.getPrivateip().equals(instance.getPrivateIpAddress())).findFirst().orElse(null);
            if (anInterface != null){
                anInterface.setActive(instance.getState().getName().equals(Constants.AWS_STATE_RUNNING));
                interfaceRepository.save(anInterface);
            } else {
                Interface newInterface = new Interface(instance, asset.get(), iaasApi.getRoutingDomain(), false);
                interfaceRepository.save(newInterface);
                added++;
            }

            if (StringUtils.isNotBlank(instance.getPublicIpAddress())) {
                Interface anInterfacePublic = asset.get().getInterfaces().stream().filter(i -> i.getPrivateip().equals(instance.getPublicIpAddress())).findFirst().orElse(null);
                if (anInterfacePublic != null) {
                    anInterfacePublic.setActive(instance.getState().getName().equals(Constants.AWS_STATE_RUNNING));
                    interfaceRepository.save(anInterfacePublic);
                } else {
                    Interface newInterface = new Interface(instance, asset.get(), routingDomainRepository.findByName(Constants.DOMAIN_INTERNET), true);
                    interfaceRepository.save(newInterface);
                    added++;
                }

            }
        } else {
            Asset newAsset = new Asset(instance, iaasApi);
            newAsset = assetRepository.save(newAsset);
            Interface newInterface = new Interface(instance, newAsset, iaasApi.getRoutingDomain(), false);
            interfaceRepository.save(newInterface);
            added++;
            if (StringUtils.isNotBlank(instance.getPublicIpAddress())){
                Interface newInterfacePublic = new Interface(instance, newAsset, routingDomainRepository.findByName(Constants.DOMAIN_INTERNET), true);
                interfaceRepository.save(newInterfacePublic);
                added++;
            }
        }
        if (added > 0)
            log.info("Successfully added {} assets for {} [AWS EC2 Plugin]", added, iaasApi.getProject().getName());
    }

    /**
     * Saving the AWS EC2 API to DB
     *
     * @param iaasApiPutModel model from fronend
     * @param project to link API to
     */
    @Override
    public void saveApi(IaasApiPutModel iaasApiPutModel, Project project) {
        IaasApi iaasApi = new IaasApi();
        iaasApi.setEnabled(false);
        iaasApi.setStatus(false);
        iaasApi.setExternal(false);
        iaasApi.setProject(project);
        iaasApi.setTenantId(iaasApiPutModel.getProjectid());
        iaasApi.setRegion(iaasApiPutModel.getRegion());
        iaasApi.setUsername(iaasApiPutModel.getUsername());
        iaasApi.setIaasApiType(iaasApiTypeRepisotory.findByName(Constants.IAAS_API_TYPE_AWS_EC2));
        iaasApi.setRoutingDomain(routingDomainRepository.findById(iaasApiPutModel.getRoutingDomainForIaasApi()).get());
        iaasApiRepository.save(iaasApi);
        String uuidToken = UUID.randomUUID().toString();
        if (vaultHelper.savePassword(iaasApiPutModel.getPassword(), uuidToken)){
            iaasApi.setPassword(uuidToken);
        } else {
            iaasApi.setPassword(iaasApiPutModel.getPassword());
        }
        iaasApiRepository.save(iaasApi);
    }

    /**
     * Verification if proper API Client is ok to process request base on frontend request
     *
     * @param iaasApiPutModel
     * @return
     */
    @Override
    public boolean canProcessRequest(IaasApiPutModel iaasApiPutModel) {
        return iaasApiPutModel.getApiType().equals(Constants.IAAS_API_TYPE_AWS_EC2);
    }
}
