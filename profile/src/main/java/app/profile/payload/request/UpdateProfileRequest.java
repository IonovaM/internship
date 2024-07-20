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

    @NotBlank(message = "Firstname cannot be blank")
    private String firstname;

    @NotBlank(message = "Lastname cannot be blank")
    private String lastname;

    @NotNull(message = "Birthday cannot be null")
    private Date birthday;

    private String bio;
}
