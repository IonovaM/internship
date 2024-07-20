package app.authserver.service;

import app.authserver.model.EnumRole;
import app.authserver.model.Role;
import app.authserver.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.Optional;

@Service
@Transactional
@RequiredArgsConstructor
public class RoleService {

    private final RoleRepository roleRepository;

    public Optional<Role> findByName(EnumRole name) {
        return roleRepository.findByName(name);
    }
}
