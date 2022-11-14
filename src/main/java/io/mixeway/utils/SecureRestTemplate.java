package io.mixeway.utils;

import io.mixeway.db.entity.IaasApi;
import io.mixeway.db.entity.Scanner;
import org.apache.http.HttpHost;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.function.Supplier;

@Component
public class SecureRestTemplate {
    @Value("${server.ssl.key-store}")
    private String keyStorePath;
    @Value("${server.ssl.key-store-password}")
    private String keyStorePassword;
    @Value("${server.ssl.trust-store}")
    private String trustStorePath;
    @Value("${server.ssl.trust-store-password}")
    private String trustStorePassword;

    public RestTemplate prepareClientWithCertificate(Scanner scanner) throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, FileNotFoundException, IOException {
        KeyStore clientStore = KeyStore.getInstance("PKCS12");
        clientStore.load(new FileInputStream(keyStorePath), keyStorePassword.toCharArray());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(clientStore, keyStorePassword.toCharArray());
        KeyManager[] kms = kmf.getKeyManagers();

        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(new FileInputStream(trustStorePath), trustStorePassword.toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        TrustManager[] tms = tmf.getTrustManagers();

        SSLContext sslContext = null;
        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kms, tms, new SecureRandom());
        CloseableHttpClient httpClient;
        if(scanner != null && scanner.getProxies() !=null){
            httpClient = HttpClients
                    .custom()
                    .setProxy(new HttpHost(scanner.getProxies().getIp(), Integer.parseInt(scanner.getProxies().getPort())))
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .setSSLContext(sslContext)
                    .build();
        }else {
            httpClient = HttpClients
                    .custom()
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .setSSLContext(sslContext)
                    .build();
        }

        ClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);

        return new RestTemplate(requestFactory);
    }
    public RestTemplate prepareClientWithCertificateWithoutTimeout(Scanner scanner) throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, FileNotFoundException, IOException {
        KeyStore clientStore = KeyStore.getInstance("PKCS12");
        clientStore.load(new FileInputStream(keyStorePath), keyStorePassword.toCharArray());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(clientStore, keyStorePassword.toCharArray());
        KeyManager[] kms = kmf.getKeyManagers();

        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(new FileInputStream(trustStorePath), trustStorePassword.toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        TrustManager[] tms = tmf.getTrustManagers();

        SSLContext sslContext = null;
        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kms, tms, new SecureRandom());
        CloseableHttpClient httpClient;
        if(scanner != null && scanner.getProxies() !=null){
            httpClient = HttpClients
                    .custom()
                    .setProxy(new HttpHost(scanner.getProxies().getIp(), Integer.parseInt(scanner.getProxies().getPort())))
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .setSSLContext(sslContext)
                    .build();
        }else {
            httpClient = HttpClients
                    .custom()
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .setSSLContext(sslContext)
                    .build();
        }

        ClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);

        return new RestTemplateBuilder().requestFactory((Supplier<ClientHttpRequestFactory>) requestFactory).setConnectTimeout(Duration.ofMinutes(5)).setReadTimeout(Duration.ofMinutes(5)).build();
        //return new RestTemplate(requestFactory);
    }

    public RestTemplate restTemplateForIaasApi(IaasApi api) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, KeyManagementException {
        //SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(new FileInputStream(trustStorePath), trustStorePassword.toCharArray());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        TrustManager[] tms = tmf.getTrustManagers();

        SSLContext sslContext = null;
        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tms, new SecureRandom());
        HttpClient httpClient;
        if (api.getExternal()) {
            //TODO zapisanie proxies w iaasapi i wybranie go tutaj
            //Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("126.204.4.20", 3128));
            httpClient = HttpClients
                    .custom()
                    .setProxy(new HttpHost("126.204.4.20", 3128))
                    .setSSLContext(sslContext)
                    .build();
            //requestFactory.setProxy(proxy);
            ClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
            return new RestTemplate(requestFactory);
        }

        return new RestTemplate();
    }

    public RestTemplate noVerificationClient(Scanner scanner) throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException{
        TrustStrategy acceptingTrustStrategy = (X509Certificate[] chain, String authType) -> true;

        SSLContextBuilder sslcontext = new SSLContextBuilder();
        HttpClient httpClient;
        sslcontext.loadTrustMaterial(null, acceptingTrustStrategy);
        if (scanner != null && scanner.getProxies() !=null) {
            httpClient = HttpClients.custom()
                    .setProxy(new HttpHost(scanner.getProxies().getIp(), Integer.parseInt(scanner.getProxies().getPort())))
                    .setSSLContext(sslcontext.build())
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .build();
        } else {
            httpClient = HttpClients.custom()
                    .setSSLContext(sslcontext.build())
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .build();
        }
        HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory() ;
        requestFactory.setConnectionRequestTimeout(200000);
        requestFactory.setConnectTimeout(200000);
        requestFactory.setReadTimeout(200000);
        requestFactory.setHttpClient(httpClient);
        RestTemplate restTemplate = new RestTemplate(requestFactory);
        return restTemplate;
    }

    public RestTemplate noVerificationClientWithCert(Scanner scanner) throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException, IOException, CertificateException, UnrecoverableKeyException {
        TrustStrategy acceptingTrustStrategy = (X509Certificate[] chain, String authType) -> true;
        KeyStore clientStore = KeyStore.getInstance("PKCS12");
        clientStore.load(new FileInputStream(keyStorePath), keyStorePassword.toCharArray());
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(clientStore, keyStorePassword.toCharArray());
        KeyManager[] kms = kmf.getKeyManagers();

        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(new FileInputStream(trustStorePath), trustStorePassword.toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        TrustManager[] tms = tmf.getTrustManagers();

        SSLContext sslContext = null;
        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kms, tms, new SecureRandom());

        HttpClient httpClient;

        if (scanner != null && scanner.getProxies() !=null) {
            httpClient = HttpClients.custom()
                    .setProxy(new HttpHost(scanner.getProxies().getIp(), Integer.parseInt(scanner.getProxies().getPort())))
                    .setSSLContext(sslContext)
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .build();
        } else {
            httpClient = HttpClients.custom()
                    .setSSLContext(sslContext)
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .build();
        }
        HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory() ;
        requestFactory.setConnectionRequestTimeout(200000);
        requestFactory.setConnectTimeout(200000);
        requestFactory.setReadTimeout(200000);
        requestFactory.setHttpClient(httpClient);
        RestTemplate restTemplate = new RestTemplate(requestFactory);
        return restTemplate;
    }

    public ResponseEntity<Object> executeRequest(RestTemplate restTemplate, HttpMethod method, String url, HttpEntity<Object> entity, Class c){
        ResponseEntity<Object> response = restTemplate.exchange(url,method, entity, c);
        return response;
    }

}
