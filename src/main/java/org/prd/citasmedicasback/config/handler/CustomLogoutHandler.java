package org.prd.citasmedicasback.config.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.prd.citasmedicasback.persistence.entity.ClientApp;
import org.prd.citasmedicasback.service.impl.ClientServiceImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Slf4j
@Component
public class CustomLogoutHandler implements LogoutHandler {

    private final ClientServiceImpl clientRepository;

    public CustomLogoutHandler(ClientServiceImpl clientRepository) {
        this.clientRepository = clientRepository;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        try {
            if (authentication != null) {
                String redirectUri = request.getParameter("post_logout_redirect_uri");
                String clientId = request.getParameter("client_id");

                log.info("Se entro al handler de logout: {}", redirectUri);

                if (!isValidLogoutRedirectUri(redirectUri, clientId)) { // Verifica que la URI es válida

                    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    response.getWriter().write("{\"status\":\"error\"}");

                }
            } else {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.getWriter().write("{\"status\":\"error\"}");
            }
        } catch (Exception e) {
            throw new RuntimeException("Logout redirect failed", e);
        }
    }

    private boolean isValidLogoutRedirectUri(String redirectUri, String clientId) {
        if (redirectUri == null || clientId == null) {
            return false;
        }
        ClientApp clientApp = clientRepository.findClientById(clientId);

        return clientApp.getRedirectUris().contains(redirectUri);
    }
}