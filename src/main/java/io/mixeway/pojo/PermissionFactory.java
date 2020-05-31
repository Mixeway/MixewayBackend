package io.mixeway.pojo;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
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
        if (user != null && (
                user.getPermisions().equals(Constants.ROLE_ADMIN) ||
                user.getPermisions().equals(Constants.ROLE_EDITOR_RUNNER) ||
                user.getUsername().equals(Constants.API_URL))){
            return true;
        } else if ( user != null && user.getPermisions().equals(Constants.ROLE_USER)){
            return user.getProjects().stream().map(Project::getId).collect(Collectors.toList()).contains(project.getId());
        } else
            return false;
    }

    private User getUserFromPrincipal(Principal principal) {
        try {
            Optional<User> userOptional = userRepository.findByUsername(principal.getName());
            if (userOptional.isPresent())
                return userOptional.get();
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
    public List<Project> getProjectForPrincipal(Principal principal){
        Optional<User> userOptional = userRepository.findByUsername(principal.getName());
        if (userOptional.isPresent() && userOptional.get().getPermisions().equals(Constants.ROLE_USER)){
            return new ArrayList<>(userOptional.get().getProjects());
        } else {
            return projectRepository.findAll();
        }
    }

}
