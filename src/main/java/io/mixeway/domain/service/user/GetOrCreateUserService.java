package io.mixeway.domain.service.user;

import io.mixeway.api.protocol.user.UserModel;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.exceptions.NotValidRoleException;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class GetOrCreateUserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final ProjectRepository projectRepository;
    ArrayList<String> roles = new ArrayList<String>() {{
        add("ROLE_USER");
        add("ROLE_PROJECT_OWNER");
        add("ROLE_AUDITOR");
        add("ROLE_ADMIN");
        add("ROLE_EDITOR_RUNNER");
        add("ROLE_API");
    }};

    public User getOrCreateUser(UserModel userModel) throws NotValidRoleException {
        Optional<User> user =  userRepository.findByCommonName(userModel.getUserCN());
        if (user.isPresent() || !roles.contains(userModel.getUserRole())) {
            throw new NotValidRoleException("Request contains not proper role " + userModel.getUserRole());
        } else {
            User userToCreate = new User();
            userToCreate.setEnabled(true);
            userToCreate.setCommonName(userModel.getUserCN());
            userToCreate.setPermisions(userModel.getUserRole());
            if (userModel.getUserRole().equals(Constants.ROLE_API)){
                userToCreate.setApiKey(UUID.randomUUID().toString());
            }
            userToCreate.setUsername(userModel.getUserUsername());
            if ( userModel.getPasswordAuth() != null && userModel.getPasswordAuth())
                userToCreate.setPassword(bCryptPasswordEncoder.encode(userModel.getUserPassword()));
            userRepository.save(userToCreate);
            if (userModel.getProjects() != null && userModel.getProjects().isPresent() && userModel.getProjects().get().size()>0)
                loadProjectPermissionsForUser(userModel.getProjects().get(),userToCreate);
            return userToCreate;
        }
    }

    public void loadProjectPermissionsForUser(List<Long> projects, User userToCreate) {
        List<Project> properProjects = new ArrayList<>();
        for (Long projectId : projects){
            Optional<Project> p = projectRepository.findById(projectId);
            p.ifPresent(properProjects::add);
        }
        userToCreate.setProjects(new HashSet<>(properProjects));
        userRepository.save(userToCreate);
    }
}
