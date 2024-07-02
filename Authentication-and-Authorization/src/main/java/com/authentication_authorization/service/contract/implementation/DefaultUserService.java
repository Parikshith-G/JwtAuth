package com.authentication_authorization.service.contract.implementation;

import com.authentication_authorization.dto.UserDTO;
import com.authentication_authorization.entities.Role;
import com.authentication_authorization.entities.User;
import com.authentication_authorization.exceptions.AppException;
import com.authentication_authorization.repository.RoleRepository;
import com.authentication_authorization.repository.UserRepository;
import com.authentication_authorization.service.contract.IDefaultUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Set;

@Service
public class DefaultUserService implements IDefaultUserService {

    private final UserRepository userRepository;

    private final RoleRepository roleRepository;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();


    @Autowired
    public DefaultUserService(UserRepository userRepository, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(username).orElseThrow(() -> new AppException("User Not Found", HttpStatus.NOT_FOUND));
        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), mapRolesToAuthorities(user.getRoles()));
    }

    private Collection<? extends GrantedAuthority> mapRolesToAuthorities(Set<Role> roles) {
        return roles.stream().map(role -> new SimpleGrantedAuthority(role.getRole())).toList();
    }

    @Override
    public User save(UserDTO dto) {
        Role role = new Role();

        if ("USER".equals(dto.role())) {
            role = roleRepository.findByRole("ROLE_USER").orElseThrow(() -> new AppException("Role not found", HttpStatus.NOT_FOUND));
        } else if ("ADMIN".equals(dto.role())) {
            role = roleRepository.findByRole("ROLE_ADMIN").orElseThrow(() -> new AppException("Role not found", HttpStatus.NOT_FOUND));
        }
        User user = new User();
        user.setEmail(dto.email());
        user.setUserName(dto.userName());
        user.setPassword(passwordEncoder.encode(dto.password()));
        user.setRole(role);
        return userRepository.save(user);
    }
}