package com.zaidMEx.security.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/AGENT")
@Tag(name = "AGENT")
public class AgentController {


    @Operation(
            description = "Get endpoint for AGENT",
            summary = "This is a summary for AGENT get endpoint",
            responses = {
                    @ApiResponse(
                            description = "Success",
                            responseCode = "200"
                    ),
                    @ApiResponse(
                            description = "Unauthorized / Invalid Token",
                            responseCode = "403"
                    )
            }

    )
    @GetMapping
    public String get() {
        return "GET:: AGENT controller";
    }
    @PostMapping
    public String post() {
        return "POST:: AGENT controller";
    }
    @PutMapping
    public String put() {
        return "PUT:: AGENT controller";
    }
    @DeleteMapping
    public String delete() {
        return "DELETE:: AGENT controller";
    }
}
