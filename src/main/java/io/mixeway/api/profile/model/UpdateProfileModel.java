/*
 * @created  2020-08-21 : 12:57
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.api.profile.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdateProfileModel {
    private String oldPassword;
    private String newPassword;
    private String newPasswordRepeat;
}