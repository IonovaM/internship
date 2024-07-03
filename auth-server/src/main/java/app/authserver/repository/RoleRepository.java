package app.authserver.repository;

import app.authserver.model.EnumRole;
import app.authserver.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Integer> {

    Optional<Role> findByName(EnumRole name);
}
