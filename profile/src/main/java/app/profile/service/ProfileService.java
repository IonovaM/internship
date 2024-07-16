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
import java.util.stream.Collectors;
import java.util.concurrent.TimeUnit;
import java.util.UUID;

@Service
public class ProfileService {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expireMs}")
    private int jwtExpirationMs;

    @Autowired
    private ProfileRepository profileRepository;

    @Autowired
    private ObjectMapper objectMapper;

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

    public void updateProfile(UUID userId, UpdateProfileRequest updateRequest) {

        Profile profile = profileRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Profile not found for user with ID: " + userId));

        profile.setBio(updateRequest.getBio());
        profile.setBirthday(updateRequest.getBirthday());
        profile.setFirstname(updateRequest.getFirstname());
        profile.setLastname(updateRequest.getLastname());
        profileRepository.save(profile);
    }
}
