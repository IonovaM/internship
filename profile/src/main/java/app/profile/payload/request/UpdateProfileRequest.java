package app.profile.payload.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.util.Date;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UpdateProfileRequest {

    @NotBlank
    private String bio;

    @NotBlank
    private Date birthday;

    @NotBlank
    private String firstname;

    @NotBlank
    private String lastname;

}
