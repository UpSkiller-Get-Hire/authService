package org.UPSkiller.Dto.Auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.UPSkiller.Domain.User.Role;

@Getter
@Setter
public class SignupRequest {

    @NotNull
    @NotBlank
    private String email;

    @NotNull
    private String password;

    @NotNull
    private Role role;
}
