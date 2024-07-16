package app.authserver.controller;

import app.authserver.exception.RoleException;
import app.authserver.jwt.JwtUtils;
import app.authserver.kafka.KafkaProducer;
import app.authserver.model.EnumRole;
import app.authserver.model.Role;
import app.authserver.model.User;
import app.authserver.payload.request.LoginRequest;
import app.authserver.payload.request.SignUpRequest;
import app.authserver.payload.response.JWTResponse;
import app.authserver.payload.response.MessageResponse;
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
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import app.authserver.model.User;
import app.authserver.payload.request.SignUpRequest;
import app.authserver.payload.response.MessageResponse;
import app.authserver.kafka.KafkaProducer;
import app.authserver.service.RoleService;
import app.authserver.service.UserService;
import app.authserver.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import app.authserver.payload.response.JWTResponse;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.time.Instant;


import app.authserver.exception.RefreshTokenException;
import app.authserver.exception.RoleException;
import app.authserver.jwt.JwtUtils;
import app.authserver.model.EnumRole;
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
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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
    private final KafkaProducer kafkaProducer; // Add KafkaProducer as a final field

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
        } else {
            roleService.findByName(EnumRole.USER).ifPresentOrElse(roles::add, () -> roles.add(new Role(EnumRole.USER)));
        }

        user.setRoles(roles);
        userService.saveUser(user);

        String jwtToken = jwtUtils.generateJwtToken(user.getId());
        jwtUtils.saveToken(user.getId(), jwtToken);
        String confirmationUrl = "http://localhost:4001/authenticate/signup/confirm?token=" + jwtToken;
        String message = String.format("User registered: %s (Email: %s). Confirm account: %s", username, email, confirmationUrl);
        kafkaProducer.sendMessage("user-registration-topic", message);

        return ResponseEntity.ok(new MessageResponse("User registered successfully! Please check your email to confirm your account."));
    }

    @PostMapping("/signup/confirm")
    public ResponseEntity<?> confirmUser(@RequestParam("token") String token) {
        if (jwtUtils.validateJwtToken(token)) {
            UUID userId = jwtUtils.getUserIdFromJwtToken(token);
            User user = userService.findById(userId)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + userId));

            user.setConfirmed(true);
            userService.saveUser(user);
            jwtUtils.deleteToken(userId);

            String message = String.format("{\"id\": \"%s\", \"username\": \"%s\"}", user.getId(), user.getUsername());
            kafkaProducer.sendMessage("user-confirmation-topic", message);

            return ResponseEntity.ok(new MessageResponse("Account confirmed successfully!"));
        }

        return ResponseEntity.badRequest().body(new MessageResponse("Error: Invalid or expired token."));
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        String username = loginRequest.getUsername();
        String password = loginRequest.getPassword();

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(username,password);

        Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        String jwt = jwtUtils.generateJwtToken(userDetails.getId());

        List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority())
                .collect(Collectors.toList());

        String refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

        JWTResponse jwtResponse = new JWTResponse();
        jwtResponse.setEmail(userDetails.getEmail());
        jwtResponse.setUsername(userDetails.getUsername());
        jwtResponse.setId(userDetails.getId());
        jwtResponse.setToken(jwt);
        jwtResponse.setRefreshToken(refreshToken);
        jwtResponse.setRoles(roles);

        return ResponseEntity.ok(jwtResponse);
    }

    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshtoken(@RequestBody TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();
        UUID userId = jwtUtils.getUserIdFromJwtToken(requestRefreshToken);

        if (jwtUtils.validateJwtToken(requestRefreshToken)) {
            String newJwt = jwtUtils.generateJwtToken(userId);
            return ResponseEntity.ok(new TokenRefreshResponse(newJwt, requestRefreshToken));
        }

        return ResponseEntity.badRequest().body(null);
    }
}






//
//    @PostMapping("/forgot/password")
//    public ResponseEntity<?> forgotPassword(@RequestBody ForgotPasswordRequest forgotPasswordRequest) {
//        String email = forgotPasswordRequest.getEmail();
///////////////////////
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
