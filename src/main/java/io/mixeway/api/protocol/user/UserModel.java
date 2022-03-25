package io.mixeway.api.protocol.user;

import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Optional;

@Getter
@Setter
public class UserModel {
    String userRole;
    String userCN;
    Boolean passwordAuth;
    String userPassword;
    String userUsername;
    String apiKey;
    Optional<List<Long>> projects;

}
