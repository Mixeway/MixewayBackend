package io.mixeway.pojo;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.parameters.P;
import org.springframework.stereotype.Component;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class PermissionFactory {
    private final UserRepository userRepository;
    private final ProjectRepository projectRepository;
    @Autowired
    public PermissionFactory(UserRepository userRepository, ProjectRepository projectRepository){
        this.userRepository = userRepository;
        this.projectRepository = projectRepository;
    }

    public boolean canUserAccessProject(Principal principal, Project project){
        User user = getUserFromPrincipal(principal);
        if (apiKeyAccessProject(principal,project)){
            return true;
        }
        else if (user != null && (
                user.getPermisions().equals(Constants.ROLE_ADMIN) ||
                user.getPermisions().equals(Constants.ROLE_AUDITOR))){
            return true;
        } else if ( user != null && (user.getPermisions().equals(Constants.ROLE_USER) || user.getPermisions().equals(Constants.ROLE_EDITOR_RUNNER))){
            return user.getProjects().stream().map(Project::getId).collect(Collectors.toList()).contains(project.getId());
        } else if (principal.getName().equals(Constants.STRATEGY_SCHEDULER)) {
            return true;
        }else
            return false;
    }

    public User getUserFromPrincipal(Principal principal) {
        try {
            Optional<User> userOptional = userRepository.findByUsername(principal.getName());
            Optional<User> userApiKey = userRepository.findByApiKey(principal.getName());
            if (userOptional.isPresent())
                return userOptional.get();
            else if (userApiKey.isPresent()){
                return userApiKey.get();
            }
            else {
                UUID test = UUID.fromString(principal.getName());
                User u = new User();
                u.setUsername(Constants.API_URL);
                u.setPermisions("ROLE_API");
                return u;
            }
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }
    private boolean apiKeyAccessProject(Principal principal, Project project){
        try {
            UUID test = UUID.fromString(principal.getName());
            Optional<User> user = userRepository.findByApiKey(principal.getName());
            if (user.isPresent() && (user.get().getPermisions().equals(Constants.ROLE_ADMIN) || user.get().getPermisions().equals(Constants.ROLE_AUDITOR))){
                return true;
            } else if (user.isPresent() && (user.get().getPermisions().equals(Constants.ROLE_USER) || user.get().getPermisions().equals(Constants.ROLE_EDITOR_RUNNER))){
                return user.get().getProjects().contains(project);
            }
            Optional<Project> optionalProject = projectRepository.findByIdAndApiKey(project.getId(), principal.getName());
            if (optionalProject.isPresent()){
                return true;
            }
        } catch (Exception e){
            return false;
        }
        return false;
    }
    public List<Project> getProjectForPrincipal(Principal principal){
        Optional<User> userOptional = userRepository.findByUsername(principal.getName());
        if (userOptional.isPresent() && (userOptional.get().getPermisions().equals(Constants.ROLE_USER) ||
                userOptional.get().getPermisions().equals(Constants.ROLE_EDITOR_RUNNER))){
            return new ArrayList<>(userOptional.get().getProjects());
        } else if (userOptional.isPresent() && (userOptional.get().getPermisions().equals(Constants.ROLE_ADMIN) ||
                userOptional.get().getPermisions().equals(Constants.ROLE_AUDITOR))) {
            return projectRepository.findAll();
        } else {
            return new ArrayList<>();
        }
    }

}
