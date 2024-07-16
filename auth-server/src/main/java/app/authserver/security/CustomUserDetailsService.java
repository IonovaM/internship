package app.authserver.security;

import app.authserver.exception.UserNotFoundException;
import app.authserver.model.User;
import app.authserver.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserService userService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userService.findByUsername(username).orElseThrow(() -> new UserNotFoundException("User " + username + " not found"));

        return new CustomUserDetails(user);
    }

    public UserDetails loadUserById(UUID userId) throws UserNotFoundException {
        User user = userService.findById(userId).orElseThrow(() -> new UserNotFoundException("User with ID " + userId + " not found"));

        return new CustomUserDetails(user);
    }
}
