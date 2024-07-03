package app.authserver.model;

import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.io.Serializable;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "Users")
@Data
@NoArgsConstructor
public class User extends IdBasedEntity implements Serializable {

    @Column(unique = true, nullable = false)
    private String username;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column
    private String securityToken;

    @Column
    private boolean active = false;

    @Column
    private Instant tokenExpiryDate;

    @ManyToMany(cascade = CascadeType.ALL,fetch = FetchType.EAGER)
    @JoinTable(name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();

    public boolean isTokenExpired() {
        return tokenExpiryDate == null || Instant.now().isAfter(tokenExpiryDate);
    }

    public void setTokenExpiryDate(Instant expiryDate) {
        this.tokenExpiryDate = expiryDate;
    }
}
