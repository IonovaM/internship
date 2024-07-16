package app.authserver.payload.response;

import lombok.Data;

import java.util.List;
import java.util.UUID;

@Data
public class JWTResponse {
    private String token;
    private String type = "Bearer";
    private String refreshToken;
    private UUID id;
    private String username;
    private String email;
    private List<String> roles;
}
