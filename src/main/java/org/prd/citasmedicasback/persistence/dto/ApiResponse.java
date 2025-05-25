package org.prd.citasmedicasback.persistence.dto;

public record ApiResponse(
        String message,
        String timestamp,
        boolean success
) {
}