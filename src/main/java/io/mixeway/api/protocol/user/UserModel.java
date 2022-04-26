package io.mixeway.api.protocol.user;

import lombok.*;

import java.util.List;
import java.util.Optional;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserModel {
    String userRole;
    String userCN;
    Boolean passwordAuth;
    String userPassword;
    String userUsername;
    String apiKey;
    Optional<List<Long>> projects;

}
