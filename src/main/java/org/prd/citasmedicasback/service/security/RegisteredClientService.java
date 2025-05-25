package org.prd.citasmedicasback.service.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.prd.citasmedicasback.persistence.dto.UserDetailsDto;
import org.prd.citasmedicasback.persistence.entity.ClientApp;
import org.prd.citasmedicasback.service.impl.ClientServiceImpl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Slf4j
@Service
public class RegisteredClientService implements RegisteredClientRepository {
    private final ClientServiceImpl clientService;


    public RegisteredClientService(ClientServiceImpl clientService) {
        this.clientService = clientService;
    }
    @Override
    public void save(RegisteredClient registeredClient) {

    }

    @Override
    public RegisteredClient findById(String id) {
        return ClientApp.toRegisteredClient(clientService.findClientById(id));
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        log.info("Buscando cliente con id: {}", clientId);

        ClientApp clientApp = clientService.findClientById(clientId);
        return ClientApp.toRegisteredClient(clientApp);
    }
}