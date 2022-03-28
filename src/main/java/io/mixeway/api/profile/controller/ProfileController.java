/*
 * @created  2020-08-21 : 12:58
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.api.profile.controller;

import io.mixeway.pojo.Status;
import io.mixeway.rest.profile.model.UpdateProfileModel;
import io.mixeway.rest.profile.model.UserProfile;
import io.mixeway.rest.profile.service.ProfileService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController()
@RequestMapping("/v2/api")
@PreAuthorize("hasAuthority('ROLE_USER')")
public class ProfileController {
    private ProfileService profileService;

    public ProfileController(ProfileService profileService){
        this.profileService = profileService;
    }

    /**
     * Method which return user profile. If password auth is set dummypassword is being sent back
     */
    @GetMapping(value = "/profile")
    public ResponseEntity<UserProfile> showUserProfile(Principal principal) {
        return profileService.showProjects(principal);
    }

    /**
     * Possibility to change password (if password auth is enabled)
     *
     * @param principal user
     * @return status
     */
    @PatchMapping(value = "/profile")
    public ResponseEntity<Status> editProfile(@RequestBody UpdateProfileModel updateProfileModel, Principal principal) {
        return profileService.editProfile(updateProfileModel, principal);
    }

    /**
     * Generation of new CICD ApiKey, previous one is deleted
     */
    @GetMapping(value = "/profile/apikey/cicd")
    public ResponseEntity<Status> regenerateCicdApiKey(Principal principal) {
        return profileService.regenerateCicdApiKey(principal);
    }
}
