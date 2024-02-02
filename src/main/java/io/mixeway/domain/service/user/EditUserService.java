package io.mixeway.domain.service.user;

import io.mixeway.api.admin.model.EditUserModel;
import io.mixeway.api.auth.model.Password;
import io.mixeway.api.protocol.user.UserModel;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class EditUserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final GetOrCreateUserService getOrCreateUserService;
    ArrayList<String> roles = new ArrayList<String>() {{
        add("ROLE_USER");
        add("ROLE_PROJECT_OWNER");
        add("ROLE_AUDITOR");
        add("ROLE_ADMIN");
        add("ROLE_EDITOR_RUNNER");
        add("ROLE_API");
    }};

    public void enable(User user){
        user.setEnabled(true);
        userRepository.save(user);
    }
    public void disable(User user){
        user.setEnabled(false);
        userRepository.save(user);
    }

    public void edit(User user, EditUserModel userModel){
        if (StringUtils.isNotBlank(userModel.getNewPassword()))
            user.setPassword(bCryptPasswordEncoder.encode(userModel.getNewPassword()));
        if (roles.contains(userModel.getRole()))
            user.setPermisions(userModel.getRole());
        userRepository.save(user);
        if (userModel.getProjects() != null  && userModel.getProjects().size()>0)
            getOrCreateUserService.loadProjectPermissionsForUser(userModel.getProjects(),user);
        userRepository.save(user);
    }

    public void increaseLogins(User user){
        user.setLogins(user.getLogins() + 1);
        userRepository.save(user);
    }
    public void increaseFailedLogins(User user){
        user.setFailedLogins(user.getFailedLogins()+1);
        if (user.getFailedLogins() > 5)
            user.setEnabled(false);
        userRepository.save(user);
    }
    public void changePassword(User user, Password password){
        user.setPassword(bCryptPasswordEncoder.encode(password.getPassword()));
        userRepository.save(user);
    }
}
