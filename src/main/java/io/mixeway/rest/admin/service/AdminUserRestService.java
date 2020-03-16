package io.mixeway.rest.admin.service;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.pojo.LogUtil;
import io.mixeway.rest.model.EditUserModel;
import io.mixeway.rest.model.UserModel;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import io.mixeway.db.entity.User;
import io.mixeway.pojo.Status;

import java.util.*;

@Service
public class AdminUserRestService {
    private static final Logger log = LoggerFactory.getLogger(AdminUserRestService.class);
    ArrayList<String> roles = new ArrayList<String>() {{
        add("ROLE_USER");
        add("ROLE_ADMIN");
        add("ROLE_EDITOR_RUNNER");
    }};
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final ProjectRepository projectRepository;

    @Autowired
    AdminUserRestService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder,
                         ProjectRepository projectRepository){
        this.userRepository = userRepository;
        this.projectRepository = projectRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public ResponseEntity<List<User>> showUsers() {
        return new ResponseEntity<>(userRepository.findAll(), HttpStatus.OK);
    }

    public ResponseEntity<Status> addUser(UserModel userModel, String name) {
        Optional<User> user =  userRepository.findByCommonName(userModel.getUserCN());
        if (user.isPresent() || !roles.contains(userModel.getUserRole())) {
            return new ResponseEntity<>(new Status("not ok"), HttpStatus.PRECONDITION_FAILED);
        } else {
            User userToCreate = new User();
            userToCreate.setEnabled(true);
            userToCreate.setCommonName(userModel.getUserCN());
            userToCreate.setPermisions(userModel.getUserRole());
            userToCreate.setUsername(userModel.getUserUsername());
            if ( userModel.getPasswordAuth())
                userToCreate.setPassword(bCryptPasswordEncoder.encode(userModel.getUserPassword()));
            userRepository.save(userToCreate);
            if (userModel.getProjects().size()>0)
                loadProjectPermissionsForUser(userModel.getProjects(),userToCreate);
            log.info("{} - Created new user {} with role {}", name, LogUtil.prepare(userToCreate.getCommonName()), LogUtil.prepare(userToCreate.getPermisions()));
            return new ResponseEntity<>(new Status("ok"), HttpStatus.CREATED);
        }
    }

    private void loadProjectPermissionsForUser(List<Long> projects, User userToCreate) {
        List<Project> properProjects = new ArrayList<>();
        for (Long projectId : projects){
            Optional<Project> p = projectRepository.findById(projectId);
            p.ifPresent(properProjects::add);
        }
        userToCreate.setProjects(new HashSet<>(properProjects));
        userRepository.save(userToCreate);
    }

    public ResponseEntity<Status> enableUser(Long id, String name) {
        Optional<User> user =  userRepository.findById(id);
        if (user.isPresent()){
            user.get().setEnabled(true);
            userRepository.save(user.get());
            log.info("{} - Enabled user {} ", name, user.get().getCommonName());
            return new ResponseEntity<>(new Status("ok"), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(new Status("not ok"), HttpStatus.NOT_FOUND);
        }
    }

    public ResponseEntity<Status> disableUser(Long id, String name) {
        Optional<User> user =  userRepository.findById(id);
        if (user.isPresent()){
            user.get().setEnabled(false);
            userRepository.save(user.get());
            log.info("{} - Disabled user {} ", name, user.get().getCommonName());
            return new ResponseEntity<>(new Status("ok"), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(new Status("not ok"), HttpStatus.NOT_FOUND);
        }
    }

    public ResponseEntity<Status> editUser(Long id, EditUserModel userModel, String name) {
        Optional<User> user =  userRepository.findById(id);
        if (user.isPresent()) {
            if (StringUtils.isNotBlank(userModel.getNewPassword()))
                user.get().setPassword(bCryptPasswordEncoder.encode(userModel.getNewPassword()));
            if (roles.contains(userModel.getRole()))
                user.get().setPermisions(userModel.getRole());
            userRepository.save(user.get());
            if (userModel.getProjects().size()>0)
                loadProjectPermissionsForUser(userModel.getProjects(),user.get());
            log.info("{} - Updated User {}", name, user.get().getUsername()!=null ? user.get().getUsername() : user.get().getCommonName());
            return new ResponseEntity<>(new Status("ok"), HttpStatus.OK);

        } else {
            return new ResponseEntity<>(new Status("not ok"), HttpStatus.NOT_FOUND);
        }
    }

    public ResponseEntity<List<Project>> showProjects() {
        return new ResponseEntity<>( projectRepository.findAll(),HttpStatus.OK);
    }
}
