package com.zaidMEx.security.controller;

import com.zaidMEx.security.auth.RegisterRequest;
import com.zaidMEx.security.models.AgentResponse;
import com.zaidMEx.security.models.AgentRquest;

import com.zaidMEx.security.services.AdminService;
import com.zaidMEx.security.user.UserRepository;
import io.swagger.v3.oas.annotations.Hidden;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/admin")
@PreAuthorize("hasRole('ADMIN')")
@RequiredArgsConstructor
public class AdminController {
    private final AdminService service;
    private final UserRepository userRepository;

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('admin:read')")
    public ResponseEntity<AgentResponse> getAgentById(@PathVariable("id") Integer id){
        AgentResponse agentResponse =
                service.getAgentById(id);
        return new ResponseEntity<>(agentResponse, HttpStatus.OK);
    }
    @PostMapping("/Test1")
   // @PreAuthorize("hasAuthority('admin:create')")
    @Hidden
    public ResponseEntity<String> registerAgent(
            @RequestBody AgentRquest request
    ) {
        return ResponseEntity.ok(service.registerAgent(request));
    }



    @DeleteMapping
    @PreAuthorize("hasAuthority('admin:delete')")
    @Hidden
    public String delete() {
        return "DELETE:: admin controller";
    }
}
