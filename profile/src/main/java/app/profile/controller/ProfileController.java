//package app.profile.controller;
//
//import app.profile.payload.request.UpdateProfileRequest;
//import app.profile.service.ProfileService;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.web.bind.annotation.*;
//
//import javax.validation.Valid;
//import java.util.UUID;
//
//@RestController
//@RequestMapping("/api/profile")
//public class ProfileController {
//
//    @Autowired
//    private ProfileService profileService;
//
//    @PutMapping("/update")
//    public ResponseEntity<String> updateProfile(@Valid @RequestBody UpdateProfileRequest updateRequest) {
//        try {
//            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//            String currentPrincipalName = authentication.getName();
//            UUID userId = profileService.getUserIdFromJwtToken(currentPrincipalName);
//            profileService.updateProfile(userId, updateRequest);
//
//            return ResponseEntity.ok("Profile updated successfully!");
//        } catch (Exception e) {
//            return ResponseEntity.badRequest().body("Failed to update profile: " + e.getMessage());
//        }
//    }
//}

package app.profile.controller;

import app.profile.payload.request.UpdateProfileRequest;
import app.profile.service.ProfileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
@RequestMapping("/api/profile")
public class ProfileController {

    private static final Logger logger = LoggerFactory.getLogger(ProfileController.class);

    private final ProfileService profileService;

    public ProfileController(ProfileService profileService) {
        this.profileService = profileService;
    }

    @PutMapping("/update")
    public ResponseEntity<String> updateProfile(@RequestHeader("Authorization") String token, @Valid @RequestBody UpdateProfileRequest updateRequest) {
        logger.info("Received request to update profile");
        try {
            // Extract token by removing the "Bearer " prefix
            if (token.startsWith("Bearer ")) {
                token = token.substring(7);
            } else {
                return ResponseEntity.badRequest().body("Invalid token format");
            }

            UUID userId = profileService.getUserIdFromJwtToken(token);

            logger.debug("Updating profile for user ID: {}", userId);
            profileService.updateProfile(userId, updateRequest);

            logger.info("Profile updated successfully for user ID: {}", userId);
            return ResponseEntity.ok("Profile updated successfully!");
        } catch (IllegalArgumentException e) {
            logger.error("Failed to update profile: Invalid user ID", e);
            return ResponseEntity.badRequest().body("Failed to update profile: Invalid user ID");
        } catch (Exception e) {
            logger.error("Failed to update profile: An unexpected error occurred", e);
            return ResponseEntity.status(500).body("Failed to update profile: An unexpected error occurred");
        }
    }
}
