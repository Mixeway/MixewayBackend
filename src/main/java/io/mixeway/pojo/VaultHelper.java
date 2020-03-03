package io.mixeway.pojo;

import io.mixeway.config.Constants;
import io.mixeway.plugins.infrastructurescan.nessus.apiclient.NessusApiClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.VaultResponseSupport;

import javax.annotation.PostConstruct;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Component
public class VaultHelper {
    private final static Logger log = LoggerFactory.getLogger(VaultHelper.class);

    @Value("${spring.cloud.vault.host}")
    private String vaultHostname;
    private final VaultOperations vaultOperations;
    @Autowired
    public VaultHelper(VaultOperations vaultOperations){
        this.vaultOperations = vaultOperations;
        warrning();

    }
    @PostConstruct
    private void warrning() {
        if (vaultHostname == null || vaultHostname.equals(Constants.DEFAULT)){
            System.out.println("####################################################################################################################");
            System.out.println("#                                                   WARRNING!                                                      #");
            System.out.println("#                                         Vault Configuration is not set                                           #");
            System.out.println("#                                         Scanner passwords will be stored                                         #");
            System.out.println("#                                         in clear text. It is recommended                                         #");
            System.out.println("#                                         To use vault.                                                            #");
            System.out.println("#                                         Read Mixeway docummentation                                              #");
            System.out.println("####################################################################################################################");
        }
    }

    public boolean savePassword(String password, String token){
        if (vaultHostname.equals(Constants.DEFAULT)){
            return false;
        } else {
            Map<String, String> upassMap = new HashMap<>();
            upassMap.put("password", password);
            vaultOperations.write("secret/" + token, upassMap);
            return true;
        }
    }

    public String getPassword(String passwordLoc){
        try {
            if (vaultHostname.equals(Constants.DEFAULT)) {
                return passwordLoc;
            } else {
                VaultResponseSupport<Map<String, Object>> password = vaultOperations.read("secret/" + passwordLoc);
                assert password != null;
                return Objects.requireNonNull(password.getData()).get(Constants.PASSWORD).toString();
            }
        } catch (NullPointerException ne) {
            log.error("Error during Vault getting password. There might be problem while integrating Vault on already working instance");
        }
        return "";

    }


}
