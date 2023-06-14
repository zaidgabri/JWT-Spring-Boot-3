package com.zaidMEx.security.models;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AgentResponse {
    private Integer id;
    private String firstname;
    private String lastname;
    private String email;
    private String confirm_email;
    private String IdentityType;
    private String Num_Identity;
    private String Birthday;
    private String Address;
    private String RCS;
    private  Integer Num_de_patente;
    private String password;
    private String tele;
}
