package org.prd.citasmedicasback.service.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.prd.citasmedicasback.persistence.dto.UserDetailsDto;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Slf4j
@Service
public class UserDetailService implements UserDetailsService {

    private final RestTemplate restTemplate;

    public UserDetailService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        String url = "http://localhost:8081/user/find/" + username;
        UserDetailsDto userDetails = null;
        log.info("Cargando usuario desde: " + url);
        try{
            ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
            ObjectMapper mapper = new ObjectMapper();
            userDetails = mapper.readValue(response.getBody(), UserDetailsDto.class);


            log.info("Usuario cargado: " + userDetails);
            if (userDetails == null) {
                throw new UsernameNotFoundException("Usuario no encontrado: " + username);
            }
        }catch (Exception e){
            throw new UsernameNotFoundException("Error al cargar el usuario: " + username, e);
        }

        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(userDetails.role().name()));
        return new User(
                userDetails.username(),
                userDetails.password(),
                userDetails.enabled(),
                true,
                true,
                !userDetails.account_locked(),
                authorities
        );
    }
}