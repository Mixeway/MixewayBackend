package io.mixeway.integrations.servicediscovery.plugin.aws.apiclient;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.ec2.model.DescribeAddressesRequest;
import com.amazonaws.services.ec2.model.DescribeAddressesResult;
import com.amazonaws.services.ec2.model.Filter;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.IaasApi;
import io.mixeway.db.entity.Project;
import io.mixeway.integrations.servicediscovery.plugin.IaasApiClient;
import io.mixeway.rest.project.model.IaasApiPutModel;

/**
 * @author gsiewruk
 */
public class AwsApiClient implements IaasApiClient {

    public void test(){
        AWSCredentials credentials = new BasicAWSCredentials("asd","dsa");

        AmazonEC2 client = AmazonEC2ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(credentials))
                .withRegion("us-west-2")
                .build();
        DescribeAddressesRequest request = new DescribeAddressesRequest().withFilters(new Filter().withName("instance-id").withValues("sad"));
        DescribeAddressesResult response = client.describeAddresses(request);
        response.getAddresses().get(0);
    }

    @Override
    public void testApiClient(IaasApi iaasApi) {
    }

    @Override
    public boolean canProcessRequest(IaasApi iaasApi) {
        return iaasApi.getIaasApiType().getName().equals(Constants.IAAS_API_TYPE_AWS_EC2) && iaasApi.getStatus() && iaasApi.getEnabled();
    }

    @Override
    public void synchronize(IaasApi iaasApi) {

    }

    @Override
    public void saveApi(IaasApiPutModel iaasApiPutModel, Project project) {

    }

    @Override
    public boolean canProcessRequest(IaasApiPutModel iaasApiPutModel) {
        return iaasApiPutModel.getApiType().equals(Constants.IAAS_API_TYPE_AWS_EC2);
    }
}
