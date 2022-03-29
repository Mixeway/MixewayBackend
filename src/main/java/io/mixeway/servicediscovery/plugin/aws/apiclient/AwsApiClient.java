package io.mixeway.servicediscovery.plugin.aws.apiclient;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.ec2.model.*;
import io.mixeway.api.project.model.IaasApiPutModel;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.Asset;
import io.mixeway.db.entity.IaasApi;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.*;
import io.mixeway.servicediscovery.plugin.IaasApiClient;
import io.mixeway.utils.VaultHelper;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * @author gsiewruk
 *
 * Class which represent plugin for AWS integration
 */
@Component
public class AwsApiClient implements IaasApiClient {

    @Value("${HTTPS_PROXY:empty}")
    String httpsProxy;
    @Value("${NO_PROXY:empty}")
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
        try {
            AWSCredentials credentials = new BasicAWSCredentials(iaasApi.getUsername(), vaultHelper.getPassword(iaasApi.getPassword()));
            setProxy();
            AmazonEC2 client = AmazonEC2ClientBuilder.standard()
                    .withCredentials(new AWSStaticCredentialsProvider(credentials))
                    .withRegion(iaasApi.getRegion())
                    .build();
            DescribeInstancesRequest request = new DescribeInstancesRequest();
            DescribeInstancesResult response = client.describeInstances(request);
            iaasApi.setStatus(true);
            iaasApiRepository.save(iaasApi);
            unsetProxy();
            log.info("[AWS EC2] Test of configuration completed {}", response.getSdkResponseMetadata().getRequestId());
        } catch (AmazonEC2Exception e) {
            log.error("Error During testing IaasAPI of type AWS EC2 for {}, reason - {}", iaasApi.getProject().getName(),e.getLocalizedMessage());
        }
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
        try {
            AWSCredentials credentials = new BasicAWSCredentials(iaasApi.getUsername(), vaultHelper.getPassword(iaasApi.getPassword()));
            setProxy();
            AmazonEC2 client = AmazonEC2ClientBuilder.standard()
                    .withCredentials(new AWSStaticCredentialsProvider(credentials))
                    .withRegion(iaasApi.getRegion())
                    .build();

            //DescribeInstancesRequest req1 = new DescribeInstancesRequest()
            //        .withFilters(new Filter().withName(Constants.AWS_VPC_ID)
            //                .withValues(iaasApi.getTenantId()));
            DescribeNetworkInterfacesRequest netInterfaceRequest = new DescribeNetworkInterfacesRequest()
                    .withFilters(new Filter()
                            .withName(Constants.AWS_VPC_ID)
                            .withValues(iaasApi.getTenantId()));
            //DescribeInstancesResult response = client.describeInstances(req1);
            DescribeNetworkInterfacesResult networkInterfacesResult = client.describeNetworkInterfaces(netInterfaceRequest);
            unsetProxy();
//        for(Reservation reservation : response.getReservations()) {
//            for (Instance instance : reservation.getInstances()) {
//                createOrUpdateAssetPrivate(instance,iaasApi);
//            }
//        }
            processSynchroOfNetworkInterfaces(iaasApi, networkInterfacesResult);
        } catch (AmazonEC2Exception e) {
            log.error("Error During Synchronizing with IaasAPI of type AWS EC2 for {}, reason - {}", iaasApi.getProject().getName(),e.getLocalizedMessage());
        }
    }

    /**
     * Method which is saving Assets and Interfaces into DB, it first change status of all assets with given scope (Project)
     * to active=false, then it create new instances and update status according to AWS API
     *
     * @param iaasApi api info to create assets
     * @param networkInterfacesResult networkInterface list from AWS EC2 API
     */
    private void processSynchroOfNetworkInterfaces(IaasApi iaasApi, DescribeNetworkInterfacesResult networkInterfacesResult) {
        int added = 0;
        // Change Status of all to false
        if (iaasApi.getProject().getAssets().size() > 0) {
            interfaceRepository.updateStateOfInterfaceByAssets(iaasApi.getProject().getAssets().stream().map(Asset::getId).collect(Collectors.toList()), false);
            assetRepository.updateStatusOfAssetByProject(iaasApi.getProject(), false);
        }
        // Loop for each Network interafce within given request of API
        for(NetworkInterface networkInterface: networkInterfacesResult.getNetworkInterfaces()){
            Optional<Interface> privateInterface = Optional.empty();
            Optional<Interface> pubicInterface = Optional.empty();
            // Check if project already contains any asset (in case it does not to aviod NullPointers)
            if (iaasApi.getProject().getAssets().size() > 0) {
                boolean isPublicAvaliable = networkInterface.getAssociation() != null && StringUtils.isNotBlank(networkInterface.getAssociation().getPublicIp());
                privateInterface = interfaceRepository.findByAssetInAndPrivateip(iaasApi.getProject().getAssets(), networkInterface.getPrivateIpAddress());
                pubicInterface = interfaceRepository.findByAssetInAndPrivateip(iaasApi.getProject().getAssets(), isPublicAvaliable ? networkInterface.getAssociation().getPublicIp() : "empty");
            }
            // If Private Interface is not present create it, otherwise change status of it accordingly
            if (!privateInterface.isPresent()){
                Asset asset = new Asset(networkInterface, iaasApi, iaasApi.getRoutingDomain());
                asset = assetRepository.save(asset);
                Interface newPrivateInterface = new Interface(networkInterface, asset, iaasApi.getRoutingDomain(), false);
                interfaceRepository.save(newPrivateInterface);
                added++;
            } else if(networkInterface.getStatus().equals(Constants.AWS_STATE_INUSE)) {
                privateInterface.get().setActive(true);
                privateInterface.get().getAsset().setActive(true);
                interfaceRepository.save(privateInterface.get());
                assetRepository.save(privateInterface.get().getAsset());
            }
            // If PublicInterface is not present otherwise change status accordingly
            if (networkInterface.getAssociation() !=null
                    && StringUtils.isNotBlank(networkInterface.getAssociation().getPublicIp())
                    && !pubicInterface.isPresent()){
                Asset asset = new Asset(networkInterface, iaasApi, routingDomainRepository.findByName(Constants.DOMAIN_INTERNET));
                asset = assetRepository.save(asset);
                Interface newPublicInterface = new Interface(networkInterface, asset, routingDomainRepository.findByName(Constants.DOMAIN_INTERNET), true);
                interfaceRepository.save(newPublicInterface);
                added++;
            } else if (networkInterface.getAssociation() !=null && StringUtils.isNotBlank(networkInterface.getAssociation().getPublicIp())
                    && pubicInterface.isPresent()
                    && networkInterface.getStatus().equals(Constants.AWS_STATE_INUSE)){
                pubicInterface.get().setActive(true);
                pubicInterface.get().getAsset().setActive(true);
                interfaceRepository.save(pubicInterface.get());
                assetRepository.save(pubicInterface.get().getAsset());
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
     */
    @Override
    public boolean canProcessRequest(IaasApiPutModel iaasApiPutModel) {
        return iaasApiPutModel.getApiType().equals(Constants.IAAS_API_TYPE_AWS_EC2);
    }
}
