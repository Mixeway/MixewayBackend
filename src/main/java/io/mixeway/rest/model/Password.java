package io.mixeway.rest.model;


import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

public class Password {
    @NotNull @Size(min = 7) String password;

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
