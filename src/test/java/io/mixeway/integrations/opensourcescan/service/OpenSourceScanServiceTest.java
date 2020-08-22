package io.mixeway.integrations.opensourcescan.service;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.net.MalformedURLException;
import java.net.URL;

import static org.junit.jupiter.api.Assertions.*;

@RunWith(SpringJUnit4ClassRunner.class)
public class OpenSourceScanServiceTest {

    @Test
    public void test() throws MalformedURLException {
        String url = "https://github.com/mixeway/mxewathub";
        URL url2 = new URL(url);
        System.out.print("host: " + url2.getHost());
        System.out.print("uri: " + url2.getPath());
    }


}