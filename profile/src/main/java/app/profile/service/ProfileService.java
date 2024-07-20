package app.profile.service;

import app.profile.model.Profile;
import app.profile.repository.ProfileRepository;
import app.profile.payload.request.UpdateProfileRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.data.redis.core.RedisTemplate;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.concurrent.TimeUnit;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class ProfileService {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expireMs}")
    private int jwtExpirationMs;

    private static final Logger logger = LoggerFactory.getLogger(ProfileService.class);
    private static final Pattern ACCOUNT_DELETION_MESSAGE_PATTERN = Pattern.compile("User account deleted: (.+?) \\(Email: (.+?)\\)");

    private ProfileRepository profileRepository;

    private ObjectMapper objectMapper;

    @Autowired
    public ProfileService(ProfileRepository profileRepository, ObjectMapper objectMapper) {
        this.profileRepository = profileRepository;
        this.objectMapper = objectMapper;
    }

    public UUID getUserIdFromJwtToken(String token) {
        String userIdString = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
        return UUID.fromString(userIdString);
    }

    @KafkaListener(topics = "user-confirmation-topic", groupId = "profile-group")
    public void consume(String message) {
        try {
            JsonNode jsonNode = objectMapper.readTree(message);
            String userId = jsonNode.get("id").asText();
            String username = jsonNode.get("username").asText();
            System.out.println(userId);

            Profile profile = new Profile();
            profile.setId(userId);
            profile.setUsername(username);

            profileRepository.save(profile);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @KafkaListener(topics = "account-deletion-topic", groupId = "profile-group")
    public void listenAccountDeletion(String message) {
        logger.info("Received account deletion message: {}", message);

        Matcher matcher = ACCOUNT_DELETION_MESSAGE_PATTERN.matcher(message);
        if (matcher.matches()) {
            String userIdString = matcher.group(1);
            UUID userId;
            try {
                userId = UUID.fromString(userIdString);
            } catch (IllegalArgumentException e) {
                logger.error("Invalid UUID format: {}", userIdString, e);
                return;
            }

            Optional<Profile> profileOpt = profileRepository.findById(userId);
            if (profileOpt.isPresent()) {
                try {
                    profileRepository.deleteById(userId);
                    logger.info("Profile deleted successfully for user ID: {}", userId);
                } catch (Exception e) {
                    logger.error("Failed to delete profile for user ID: {}", userId, e);
                }
            } else {
                logger.warn("Profile not found for user ID: {}", userId);
            }
        } else {
            logger.error("Account deletion message format is incorrect: {}", message);
        }
    }

    public void updateProfile(UUID userId, UpdateProfileRequest updateRequest) {

        Profile profile = profileRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Profile not found for user with ID: " + userId));

        profile.setBio(updateRequest.getBio());
        profile.setBirthday(updateRequest.getBirthday());
        profile.setFirstname(updateRequest.getFirstname());
        profile.setLastname(updateRequest.getLastname());
        profile.setLastname(updateRequest.getBio());
        profileRepository.save(profile);
    }

    public Optional<Profile> getProfileById(UUID id) {
        return profileRepository.findById(id);
    }
}
