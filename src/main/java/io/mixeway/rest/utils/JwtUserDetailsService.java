package io.mixeway.rest.utils;

import io.mixeway.db.entity.Project;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.Settings;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.SettingsRepository;
import io.mixeway.db.repository.UserRepository;

import java.util.*;

@Service
public class JwtUserDetailsService implements UserDetailsService {
    private UserRepository userRepository;
    private ProjectRepository projectRepository;
    private SettingsRepository settingsRepository;

    @Autowired
    public JwtUserDetailsService(SettingsRepository settingsRepository, UserRepository userRepository, ProjectRepository projectRepository){
        this.settingsRepository = settingsRepository;
        this.userRepository = userRepository;
        this.projectRepository = projectRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<io.mixeway.db.entity.User> user = userRepository.findByCommonName(username);
        Optional<io.mixeway.db.entity.User> user2 = userRepository.findByUsername(username);
        if (user.isPresent()){
            return new User(user.get().getCommonName(),"",getAuthoritiesForUser(user.get().getPermisions()));
        } else if (user2.isPresent()) {
            return new User(user2.get().getUsername(),"",getAuthoritiesForUser(user2.get().getPermisions()));
        } else {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }

    }

    private List<GrantedAuthority> getAuthoritiesForUser(String role){
        if (role.equals(Constants.ROLE_ADMIN))
            return AuthorityUtils.commaSeparatedStringToAuthorityList(Constants.ROLE_USER + "," + Constants.ROLE_EDITOR_RUNNER + "," + Constants.ROLE_ADMIN);
        else if (role.equals(Constants.ROLE_EDITOR_RUNNER))
            return AuthorityUtils.commaSeparatedStringToAuthorityList(Constants.ROLE_USER + "," + Constants.ROLE_EDITOR_RUNNER);
        else
            return AuthorityUtils.commaSeparatedStringToAuthorityList(Constants.ROLE_USER );


    }

    UserDetails loadUserByApiKeyAndRequestUri(String username, String requestURI) {
        try {
            String[] locations = requestURI.split("/");
            Settings settings = settingsRepository.findAll().stream().findFirst().orElse(null);
            assert settings != null;
            if ( settings.getMasterApiKey() != null && username.equals(settings.getMasterApiKey()))
                return new User(username, "", AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_API"));
            if (locations.length > 0 && locations[1].equals(Constants.API_URL)) {
                if (locations[2].equals(Constants.KOORDYNATOR_API_URL) || locations[3].equals(Constants.SCANMANAGE_API)) {
                    if (settings.getMasterApiKey() != null && username.equals(settings.getMasterApiKey()))
                        return new User(username, "", AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_API"));
                    else
                        throw new UsernameNotFoundException("Tried to access vulnerabilities API with " + username);
                } else {
                    Optional<Project> project = projectRepository.findByIdAndApiKey(Long.valueOf(locations[3]),username);
                    if (project.isPresent() || (settings.getMasterApiKey() != null && username.equals(settings.getMasterApiKey()))) {
                        return new User(username, "", AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_API"));
                    } else {
                        throw new UsernameNotFoundException("No permisions");
                    }

                }
            }
            throw new UsernameNotFoundException("User not found");
        } catch (NumberFormatException | ArrayIndexOutOfBoundsException ex) {
            throw new UsernameNotFoundException("User not found");
        }
    }
}
