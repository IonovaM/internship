package app.authserver.controller;

import app.authserver.exception.RefreshTokenException;
import app.authserver.exception.RoleException;
import app.authserver.jwt.JwtUtils;
import app.authserver.model.EnumRole;
import app.authserver.model.RefreshToken;
import app.authserver.model.Role;
import app.authserver.model.User;
import app.authserver.payload.request.LoginRequest;
import app.authserver.payload.request.SignUpRequest;
import app.authserver.payload.request.TokenRefreshRequest;
import app.authserver.payload.response.JWTResponse;
import app.authserver.payload.response.MessageResponse;
import app.authserver.payload.response.TokenRefreshResponse;
import app.authserver.security.CustomUserDetails;
import app.authserver.service.RefreshTokenService;
import app.authserver.service.RoleService;
import app.authserver.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import app.authserver.model.User;
import app.authserver.service.UserService;
import app.authserver.payload.request.*;
//import app.authserver.util.EmailUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.Instant;
import java.util.Optional;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/authenticate")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final RoleService roleService;
    private final RefreshTokenService refreshTokenService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder encoder;
    private final JwtUtils jwtUtils;

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody SignUpRequest signUpRequest) {

        String username = signUpRequest.getUsername();
        String email = signUpRequest.getEmail();
        String password = signUpRequest.getPassword();
        Set<String> strRoles = signUpRequest.getRoles();
        Set<Role> roles = new HashSet<>();

        if(userService.existsByUsername(username)){
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }
        if(userService.existsByEmail(email)){
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already taken!"));
        }

        User user = new User();
        user.setEmail(email);
        user.setUsername(username);
        user.setPassword(encoder.encode(password));

        if (strRoles != null) {
            strRoles.forEach(role -> {
                switch (role) {
                    case "ADMIN":
                        Role adminRole = null;
                        if(roleService.findByName(EnumRole.ADMIN).isEmpty()){
                            adminRole = new Role(EnumRole.ADMIN);
                        }else{
                            adminRole = roleService.findByName(EnumRole.ADMIN)
                                    .orElseThrow(() -> new RoleException("Error: Admin Role is not found."));
                        }
                        roles.add(adminRole);

                        break;
                    default:
                        Role userRole = null;
                        if(roleService.findByName(EnumRole.USER).isEmpty()){
                            userRole = new Role(EnumRole.USER);
                        }else{
                            userRole = roleService.findByName(EnumRole.USER)
                                    .orElseThrow(() -> new RoleException("Error: User Role is not found."));
                        }
                        roles.add(userRole);
                }
            });
        }else{
            roleService.findByName(EnumRole.USER).ifPresentOrElse(roles::add, () -> roles.add(new Role(EnumRole.USER)));
        }

        user.setRoles(roles);
        userService.saveUser(user);
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
//        TODO: publish event
//        TODO: confirm
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        String username = loginRequest.getUsername();
        String password = loginRequest.getPassword();

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(username,password);

        Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        String jwt = jwtUtils.generateJwtToken(userDetails.getUsername());

        List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority())
                .collect(Collectors.toList());

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

        JWTResponse jwtResponse = new JWTResponse();
        jwtResponse.setEmail(userDetails.getEmail());
        jwtResponse.setUsername(userDetails.getUsername());
        jwtResponse.setId(userDetails.getId());
        jwtResponse.setToken(jwt);
        jwtResponse.setRefreshToken(refreshToken.getToken());
        jwtResponse.setRoles(roles);

        return ResponseEntity.ok(jwtResponse);
    }

//    @GetMapping("/signup/confirm")
//    public ResponseEntity<?> confirmAccount(@RequestParam("token") String token) {
//        User user = userService.findBySecurityToken(token)
//                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Token not found"));
//
//        if (user.isTokenExpired()) {
//            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new MessageResponse("Error: Token has expired!"));
//        }
//        return ResponseEntity.ok(new MessageResponse("Token is valid. Please confirm your account by sending a POST request."));
//    }
//
//    @PostMapping("/signup/confirm")
//    public ResponseEntity<?> confirmAccountPost(@RequestParam("token") String token) {
//        User user = userService.findBySecurityToken(token)
//                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Token not found"));
//        if (user.isTokenExpired()) {
//            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new MessageResponse("Error: Token has expired!"));
//        }
//
//        try {
//            user.setActive(true);
//            user.setSecurityToken(null);
//            userService.saveUser(user);
//            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
//            Authentication authentication = authenticationManager.authenticate(authToken);
//            SecurityContextHolder.getContext().setAuthentication(authentication);
//
//            String jwt = jwtUtils.generateJwtToken(user.getUsername());
//            return ResponseEntity.ok(new MessageResponse("Account confirmed successfully! Token: " + jwt));
//        } catch (Exception e) {
//            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new MessageResponse("Something went wrong."));
//        }
//    }
//
//    @PostMapping("/forgot/password")
//    public ResponseEntity<?> forgotPassword(@RequestBody ForgotPasswordRequest forgotPasswordRequest) {
//        String email = forgotPasswordRequest.getEmail();
//        Optional<User> optionalUser = userService.findByEmail(email);
//
//        if (optionalUser.isPresent()) {
//            User user = optionalUser.get();
//            try {
//                String token = tokenUtil.generateToken();
//                user.setSecurityToken(token);
//                user.setTokenExpiryDate(Instant.now().plusSeconds(3600)); // 1 hour expiry
//                userService.saveUser(user);
//                emailUtil.sendResetPasswordEmail(user);
//                return ResponseEntity.ok(new MessageResponse("A reset password link sent to your email. Please check."));
//            } catch (Exception e) {
//                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new MessageResponse("Something went wrong."));
//            }
//        }
//
//        return ResponseEntity.badRequest().body(new MessageResponse("Email address is not registered with us."));
//    }
//
//    @PostMapping("/password/reset")
//    public ResponseEntity<?> resetPassword(@RequestParam("token") String token, @RequestBody ResetPasswordRequest resetPasswordRequest) {
//        Optional<User> optionalUser = userService.findBySecurityToken(token);
//
//        if (optionalUser.isPresent()) {
//            User user = optionalUser.get();
//            if (!user.isTokenExpired()) {
//                String password = resetPasswordRequest.getPassword();
//                String confirmPassword = resetPasswordRequest.getConfirmPassword();
//
//                if (!password.equals(confirmPassword)) {
//                    return ResponseEntity.badRequest().body(new MessageResponse("Your new password fields do not match."));
//                } else if (!Pattern.matches("(?=^.{8,}$)(?=.*\\d)(?=.*[!@#$%^&*]+)(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$", password)) {
//                    return ResponseEntity.badRequest().body(new MessageResponse("Please choose a strong password. It contains at least one alphabet, number, and one special character."));
//                } else {
//                    user.setPassword(password);
//                    user.setSecurityToken(null);
//                    userService.saveUser(user);
//                    return ResponseEntity.ok(new MessageResponse("Your password is changed successfully. Please login."));
//                }
//            } else {
//                return ResponseEntity.badRequest().body(new MessageResponse("Token has expired!"));
//            }
//        } else {
//            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Token not found");
//        }
//    }
//
//    @PostMapping("/change/password")
//    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest changePasswordRequest) {
//        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//        User user = userService.findByUsername(auth.getName()).orElseThrow(() -> new RuntimeException("User not found"));
//
//        String oldPassword = changePasswordRequest.getOldPassword();
//        String newPassword = changePasswordRequest.getNewPassword();
//        String confirmPassword = changePasswordRequest.getConfirmPassword();
//
//        if ("test_user".equals(user.getUsername())) {
//            return ResponseEntity.badRequest().body(new MessageResponse("Test user limited to read-only access."));
//        } else if (!user.checkPassword(oldPassword)) {
//            return ResponseEntity.badRequest().body(new MessageResponse("Your old password is incorrect."));
//        } else if (!newPassword.equals(confirmPassword)) {
//            return ResponseEntity.badRequest().body(new MessageResponse("Your new password fields do not match."));
//        } else if (!Pattern.matches("(?=^.{8,}$)(?=.*\\d)(?=.*[!@#$%^&*]+)(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$", newPassword)) {
//            return ResponseEntity.badRequest().body(new MessageResponse("Please choose a strong password. It contains at least one alphabet, number, and one special character."));
//        } else {
//            user.setPassword(newPassword);
//            userService.saveUser(user);
//            return ResponseEntity.ok(new MessageResponse("Your password changed successfully."));
//        }
//    }
//
//    @PostMapping("/change/email")
//    public ResponseEntity<?> changeEmail(@RequestBody ChangeEmailRequest changeEmailRequest) {
//        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//        User user = userService.findByUsername(auth.getName()).orElseThrow(() -> new RuntimeException("User not found"));
//
//        String email = changeEmailRequest.getEmail();
//
//        if ("test_user".equals(user.getUsername())) {
//            return ResponseEntity.badRequest().body(new MessageResponse("Guest user limited to read-only access."));
//        } else if (email.equals(user.getEmail())) {
//            return ResponseEntity.badRequest().body(new MessageResponse("Email is already verified with your account."));
//        } else if (userService.existsByEmail(email)) {
//            return ResponseEntity.badRequest().body(new MessageResponse("Email address is already registered with us."));
//        } else {
//            try {
//                String token = tokenUtil.generateToken();
//                user.setChangeEmail(email);
//                user.setSecurityToken(token);
//                user.setTokenExpiryDate(Instant.now().plusSeconds(3600)); // 1 hour expiry
//                userService.saveUser(user);
//                emailUtil.sendChangeEmailEmail(user);
//                return ResponseEntity.ok(new MessageResponse("A reset email link sent to your new email address. Please verify."));
//            } catch (Exception e) {
//                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new MessageResponse("Something went wrong."));
//            }
//        }
//    }

//    @PostMapping("/refreshtoken")
//    public ResponseEntity<?> refreshtoken(@RequestBody TokenRefreshRequest request) {
//
//        String requestRefreshToken = request.getRefreshToken();
//        RefreshToken token = refreshTokenService.findByToken(requestRefreshToken)
//                .orElseThrow(() -> new RefreshTokenException(requestRefreshToken + "Refresh token is not in database!"));
//
//        RefreshToken deletedToken = refreshTokenService.verifyExpiration(token);
//        User userRefreshToken = deletedToken.getUser();
//        String newToken = jwtUtils.generateTokenFromUsername(userRefreshToken.getUsername());
//        return ResponseEntity.ok(new TokenRefreshResponse(newToken, requestRefreshToken));
//    }
}
