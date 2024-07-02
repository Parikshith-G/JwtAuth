package com.authentication_authorization.service.contract;

import com.authentication_authorization.dto.UserDTO;
import com.authentication_authorization.entities.User;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface IDefaultUserService extends UserDetailsService {
    User save(UserDTO dto);

}
