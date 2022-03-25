package io.mixeway.api.admin.service;

import io.mixeway.api.admin.model.EditUserModel;
import io.mixeway.api.protocol.user.UserModel;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import io.mixeway.domain.exceptions.NotValidRoleException;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.user.EditUserService;
import io.mixeway.domain.service.user.FindUserService;
import io.mixeway.domain.service.user.GetOrCreateUserService;
import io.mixeway.utils.LogUtil;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@Log4j2
@RequiredArgsConstructor
public class AdminUserRestService {
    private final FindUserService findUserService;
    private final GetOrCreateUserService getOrCreateUserService;
    private final EditUserService editUserService;
    private final FindProjectService findProjectService;

    public ResponseEntity<List<User>> showUsers() {
        return new ResponseEntity<>(findUserService.findAll(), HttpStatus.OK);
    }

    public ResponseEntity<Status> addUser(UserModel userModel, String name) {
        try {
            User userToCreate = getOrCreateUserService.getOrCreateUser(userModel);
            log.info("{} - Created new user {} with role {}", name, LogUtil.prepare(userToCreate.getCommonName()), LogUtil.prepare(userToCreate.getPermisions()));
            return new ResponseEntity<>(new Status("ok",userToCreate.getApiKey()), HttpStatus.CREATED);
        } catch (NotValidRoleException ex) {
            log.error("[Admin] Error during adding user, user exist or role is wrong");
            return new ResponseEntity<>(new Status("not ok"), HttpStatus.PRECONDITION_FAILED);
        }
    }


    public ResponseEntity<Status> enableUser(Long id, String name) {
        Optional<User> user =  findUserService.findById(id);
        if (user.isPresent()){
            editUserService.enable(user.get());
            log.info("{} - Enabled user {} ", name, user.get().getCommonName());
            return new ResponseEntity<>(new Status("ok"), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(new Status("not ok"), HttpStatus.NOT_FOUND);
        }
    }

    public ResponseEntity<Status> disableUser(Long id, String name) {
        Optional<User> user =  findUserService.findById(id);
        if (user.isPresent()){
            editUserService.disable(user.get());
            log.info("{} - Disabled user {} ", name, user.get().getCommonName());
            return new ResponseEntity<>(new Status("ok"), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(new Status("not ok"), HttpStatus.NOT_FOUND);
        }
    }

    public ResponseEntity<Status> editUser(Long id, EditUserModel userModel, String name) {
        Optional<User> user =  findUserService.findById(id);
        if (user.isPresent()) {
            editUserService.edit(user.get(), userModel);
            log.info("[Admin] {} edits user with id={}", name, id);
            return new ResponseEntity<>(new Status("ok"), HttpStatus.OK);

        } else {
            return new ResponseEntity<>(new Status("not ok"), HttpStatus.NOT_FOUND);
        }
    }

    public ResponseEntity<List<Project>> showProjects() {
        return new ResponseEntity<>( findProjectService.findAll(),HttpStatus.OK);
    }
}
