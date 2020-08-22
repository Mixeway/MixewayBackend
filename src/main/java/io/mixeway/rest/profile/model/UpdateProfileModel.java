/*
 * @created  2020-08-21 : 12:57
 * @project  MixewayScanner
 * @author   siewer
 */
package io.mixeway.rest.profile.model;

public class UpdateProfileModel {
    private String oldPassword;
    private String newPassword;
    private String newPasswordRepeat;


    public String getOldPassword() {
        return oldPassword;
    }

    public void setOldPassword(String oldPassword) {
        this.oldPassword = oldPassword;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }

    public String getNewPasswordRepeat() {
        return newPasswordRepeat;
    }

    public void setNewPasswordRepeat(String newPasswordRepeat) {
        this.newPasswordRepeat = newPasswordRepeat;
    }
}