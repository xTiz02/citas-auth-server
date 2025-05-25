package org.prd.citasmedicasback.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.prd.citasmedicasback.persistence.entity.ClientApp;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Slf4j
@Service
public class ClientServiceImpl {

    private final RestTemplate restTemplate;

    public ClientServiceImpl(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }


    public ClientApp findClientById(String clientId) {
        log.info("Buscando cliente con id: {}", clientId);

        String url = "http://localhost:8081/client/find/" + clientId;
        ClientApp clientApp = null;
        log.info("Cargando usuario desde: " + url);
        try{
            ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
            log.info("Respuesta del servidor: " + response.getBody());
            ObjectMapper mapper = new ObjectMapper();
            clientApp = mapper.readValue(response.getBody(), ClientApp.class);


            log.info("Usuario cargado: " + clientApp);
            if (clientApp == null) {
                throw new UsernameNotFoundException("Cliente no encontrado: " + clientId);
            }
        }catch (Exception e){
            throw new UsernameNotFoundException("Error al cargar el Cliente: " + clientId, e);
        }

        return (clientApp);
    }
}