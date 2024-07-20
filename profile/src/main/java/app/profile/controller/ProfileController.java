package app.profile.controller;
import app.profile.jwt.JwtUtils;
import app.profile.model.Profile;
import app.profile.repository.ProfileRepository;
import app.profile.payload.response.MessageResponse;
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
    private final JwtUtils jwtUtils;
    private final ProfileRepository profileRepository;

    @Autowired
    public ProfileController(ProfileService profileService, JwtUtils jwtUtils, ProfileRepository profileRepository) {
        this.profileService = profileService;
        this.jwtUtils = jwtUtils;
        this.profileRepository = profileRepository;
    }


    @PutMapping("/update")
    public ResponseEntity<String> updateProfile(@RequestHeader("Authorization") String token, @Valid @RequestBody UpdateProfileRequest updateRequest) {
        logger.info("Received request to update profile");
        try {
            if (token.startsWith("Bearer ")) {
                token = token.substring(7);
            } else {
                return ResponseEntity.badRequest().body("Invalid token format");
            }

            UUID userId = jwtUtils.getUserIdFromJwtToken(token);

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



    @GetMapping("/me")
    public ResponseEntity<?> getProfile(@RequestHeader("Authorization") String token) {
        try {
            logger.info("Received request to get profile with token: {}", token);

            if (token.startsWith("Bearer ")) {
                token = token.substring(7);
            } else {
                logger.warn("Invalid token format");
                return ResponseEntity.badRequest().body(new MessageResponse("Invalid token format"));
            }

            if (!jwtUtils.validateJwtToken(token)) {
                logger.warn("Invalid or expired token");
                return ResponseEntity.status(403).body(new MessageResponse("Error: Invalid or expired token."));
            }

            UUID userId = jwtUtils.getUserIdFromJwtToken(token);
            logger.info("Extracted user ID from token: {}", userId);

            return profileService.getProfileById(userId)
                    .map(ResponseEntity::ok)
                    .orElse(ResponseEntity.notFound().build());
        } catch (Exception e) {
            logger.error("Error retrieving profile", e);
            return ResponseEntity.badRequest().body(new MessageResponse("Error retrieving profile: " + e.getMessage()));
        }
    }
}
