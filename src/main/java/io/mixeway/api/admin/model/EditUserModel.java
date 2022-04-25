package io.mixeway.api.admin.model;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class EditUserModel {
    String newPassword;
    String role;
    List<Long> projects;
}
