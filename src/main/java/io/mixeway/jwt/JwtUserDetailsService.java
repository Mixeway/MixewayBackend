package io.mixeway.jwt;

import io.mixeway.config.Constants;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.SettingsRepository;
import io.mixeway.db.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class JwtUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;
    private final ProjectRepository projectRepository;
    private final SettingsRepository settingsRepository;

    @Autowired
    public JwtUserDetailsService(SettingsRepository settingsRepository, UserRepository userRepository, ProjectRepository projectRepository){
        this.settingsRepository = settingsRepository;
        this.userRepository = userRepository;
        this.projectRepository = projectRepository;
    }

    /**
     * Loading user by username when used password
     *
     * @param username to load
     * @return userDetails entity
     */
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

    /**
     * Handle permission granting
     *
     */
    private List<GrantedAuthority> getAuthoritiesForUser(String role){
        switch (role) {
            case Constants.ROLE_ADMIN:
                return AuthorityUtils.commaSeparatedStringToAuthorityList(
                        Constants.ROLE_USER + "," +
                                Constants.ROLE_EDITOR_RUNNER + "," +
                                Constants.ROLE_ADMIN + "," +
                                Constants.ROLE_AUDITOR + "," +
                                Constants.ROLE_PROJECT_OWNER + "," +
                                Constants.ROLE_API);
            case Constants.ROLE_AUDITOR:
                return AuthorityUtils.commaSeparatedStringToAuthorityList(
                        Constants.ROLE_USER + "," +
                                Constants.ROLE_AUDITOR + "," +
                                Constants.ROLE_EDITOR_RUNNER);
            case Constants.ROLE_EDITOR_RUNNER:
                return AuthorityUtils.commaSeparatedStringToAuthorityList(Constants.ROLE_USER + "," + Constants.ROLE_EDITOR_RUNNER + "," + Constants.ROLE_API);
            case Constants.ROLE_API:
                return AuthorityUtils.commaSeparatedStringToAuthorityList(Constants.ROLE_API + "," + Constants.ROLE_USER);
            case Constants.ROLE_PROJECT_OWNER:
                return AuthorityUtils.commaSeparatedStringToAuthorityList(Constants.ROLE_API + "," + Constants.ROLE_USER + "," + Constants.ROLE_PROJECT_OWNER);

            default:
                return AuthorityUtils.commaSeparatedStringToAuthorityList(Constants.ROLE_USER + "," + Constants.ROLE_API);
        }


    }

    /**
     * Return User Details for API Key Access
     */
    UserDetails loadUserByApiKeyAndRequestUri(String username, String requestURI) {
        try {
            boolean isMasterKeyUsed = settingsRepository.findAll().stream().findFirst().orElse(null).getMasterApiKey().equals(username);
            Optional<io.mixeway.db.entity.User> userApiKey = userRepository.findByApiKey(username);
            List<Project> projectApiKey = projectRepository.findByApiKey(username);
            if (isMasterKeyUsed){
                return new User("admin", "", AuthorityUtils.commaSeparatedStringToAuthorityList(
                        "," +Constants.ROLE_USER
                                + "," +Constants.ROLE_EDITOR_RUNNER
                                + "," +Constants.ROLE_API
                                + "," +Constants.ROLE_AUDITOR
                                + "," +Constants.ROLE_ADMIN  ));
            } else if (userApiKey.isPresent()){
                return new User(userApiKey.get().getUsername(),"",getAuthoritiesForUser(userApiKey.get().getPermisions()));
            } else if (projectApiKey.size() > 0) {
                return new User(username,"",getAuthoritiesForUser(Constants.ROLE_EDITOR_RUNNER));
            } else {
                throw new UsernameNotFoundException("No permissions");
            }
        } catch (NumberFormatException | ArrayIndexOutOfBoundsException ex) {
            throw new UsernameNotFoundException("User not found");
        }
    }
}
