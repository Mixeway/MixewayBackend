package io.mixeway.rest.admin.controller;

import io.mixeway.db.entity.Project;
import io.mixeway.rest.model.EditUserModel;
import io.mixeway.rest.model.UserModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import io.mixeway.db.entity.User;
import io.mixeway.pojo.Status;
import io.mixeway.rest.admin.service.AdminUserRestService;

import java.security.*;
import java.util.List;

@RestController()
@RequestMapping("/v2/api/admin")
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class AdminUserRestController {
    private final AdminUserRestService adminRestService;

    @Autowired
    AdminUserRestController(AdminUserRestService adminRestService){
        this.adminRestService = adminRestService;
    }

    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping(value = "/users")
    public ResponseEntity<List<User>> showUsers() {
        return adminRestService.showUsers();
    }
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping(value = "/projects")
    public ResponseEntity<List<Project>> showProjects() {
        return adminRestService.showProjects();
    }

    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PutMapping(value = "/user/add")
    public ResponseEntity<Status> addUser(@RequestBody UserModel userModel, Principal principal) {
        return adminRestService.addUser(userModel,principal.getName());
    }

    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PatchMapping(value = "/user/{id}")
    public ResponseEntity<Status> editUser(@PathVariable("id") Long id, @RequestBody EditUserModel userModel, Principal principal) {
        return adminRestService.editUser(id, userModel,principal.getName());
    }

    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PutMapping(value = "/user/{id}/enable")
    public ResponseEntity<Status> enableUser(@PathVariable("id")Long id, Principal principal) {
        return adminRestService.enableUser(id,principal.getName());
    }

    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PutMapping(value = "/user/{id}/disable")
    public ResponseEntity<Status> disableUser(@PathVariable("id")Long id, Principal principal) {
        return adminRestService.disableUser(id,principal.getName());
    }
}
