package io.mixeway.api.admin.controller;

import io.mixeway.api.admin.model.EditUserModel;
import io.mixeway.api.admin.service.AdminUserRestService;
import io.mixeway.api.protocol.user.UserModel;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import io.mixeway.utils.Status;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;

@RestController()
@RequestMapping("/v2/api/admin")
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class AdminUserRestController {
    private final AdminUserRestService adminRestService;

    AdminUserRestController(AdminUserRestService adminRestService){
        this.adminRestService = adminRestService;
    }


    /**
     * Returning list of users defined in DB
     *
     * @return List of users
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "List returned")
//    })
//    @ApiOperation(value = "Show Users.",
//            notes = "Show details of already saved users")
    @GetMapping(value = "/users")
    public ResponseEntity<List<User>> showUsers() {
        return adminRestService.showUsers();
    }

    /**
     * Return list of projects for linking permissions for new users
     *
     * @return List of projects
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "List returned")
//    })
//    @ApiOperation(value = "Show Projects",
//            notes = "Show details of avaliable projects defined. Used for permission handling of new user creation.")
    @GetMapping(value = "/projects")
    public ResponseEntity<List<Project>> showProjects() {
        return adminRestService.showProjects();
    }

    /**
     * Create new user
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 201, message = "User created"),
//            @ApiResponse(code = 417, message = "Request not valid")
//    })
//    @ApiOperation(value = "Add new user",
//            notes = "Adding new user")
    @PutMapping(value = "/user/add")
    public ResponseEntity<Status> addUser(@RequestBody UserModel userModel, Principal principal) {
        return adminRestService.addUser(userModel,principal.getName());
    }


    /**
     * Editing user
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "Value set"),
//            @ApiResponse(code = 417, message = "Not valid Cron expression")
//    })
//    @ApiOperation(value = "User Edit",
//            notes = "Possibility to edit user - change password or permissions")
    @PatchMapping(value = "/user/{id}")
    public ResponseEntity<Status> editUser(@PathVariable("id") Long id, @RequestBody EditUserModel userModel, Principal principal) {
        return adminRestService.editUser(id, userModel,principal.getName());
    }

    /**
     * Enable access for user by ID
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "User Enabled")
//    })
//    @ApiOperation(value = "Enable access for user",
//            notes = "Enable access for user - user has possibility to perform requests")
    @PutMapping(value = "/user/{id}/enable")
    public ResponseEntity<Status> enableUser(@PathVariable("id")Long id, Principal principal) {
        return adminRestService.enableUser(id,principal.getName());
    }

    /**
     * Disable access for user by ID
     *
     * @return status
     */
//    @ApiResponses(value = {
//            @ApiResponse(code = 200, message = "User Disabled")
//    })
//    @ApiOperation(value = "Disable access for user",
//            notes = "Disable access for user - disabled users cannot perform any requests")
    @PutMapping(value = "/user/{id}/disable")
    public ResponseEntity<Status> disableUser(@PathVariable("id")Long id, Principal principal) {
        return adminRestService.disableUser(id,principal.getName());
    }
}



