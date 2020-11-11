package io.mixeway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * @author gsiewruk
 */
@Component
@ConfigurationProperties("server")
public class ServerProperties {
    private int port;

    @Override
    public String toString() {
        return "ServerProperties{" +
                "port=" + port +
                '}';
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }
}
