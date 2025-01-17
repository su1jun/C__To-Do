package org.zerock.todo.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.zerock.todo.domain.APIUser;
import org.zerock.todo.dto.APIUserDTO;
import org.zerock.todo.repository.APIUserRepository;

import java.util.List;
import java.util.Optional;

@Log4j2
@RequiredArgsConstructor
@Service
public class APIUserDetailsService implements UserDetailsService {
    //주입
    private final APIUserRepository apiUserRepository;
    @Override
    public UserDetails loadUserByUsername(
            String username
    ) throws UsernameNotFoundException {
        log.info("----------security.APIUserDetailsService.loadUserByUsername(사용자 정보 로드)");

        Optional<APIUser> result = apiUserRepository.findById(username);

        APIUser apiUser = result.orElseThrow(
                () -> new UsernameNotFoundException("Cannot find mid")
        );

        APIUserDTO dto =  new APIUserDTO(
                apiUser.getMid(),
                apiUser.getMpw(),
                List.of(new SimpleGrantedAuthority("ROLE_USER")));

        log.info(dto);

        return dto;
    }
}
