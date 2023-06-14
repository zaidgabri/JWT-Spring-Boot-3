package com.zaidMEx.security;

import com.zaidMEx.security.auth.AuthenticationService;
import com.zaidMEx.security.auth.RegisterRequest;
import com.zaidMEx.security.user.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;


@SpringBootApplication
public class SecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(
			AuthenticationService service
	) {
		return args -> {
			var admin = RegisterRequest.builder()
			.firstname("zaid")
            .lastname("Gabri")
            .email("zaid@gmail.com")
            .confirm_email("zaid@gmail.com")
            .IdentityType("CIN")
            .Num_Identity("0987567")
            .Birthday("23-34-3333")
            .Address("marrackech")
            .RCS("0-0987cvbnmmnb")
            .Num_de_patente(Integer.valueOf("0777"))
            .password("password")
            .role(Role.ADMIN)
            .tele("08765098766")
            .build();};}
		//	System.out.println("Admin token: " + service.registerADMIN(admin).};;}
/*
			var manager = RegisterRequest.builder()
					.firstname("Admin")
					.lastname("Admin")
					.email("manager@mail.com")
					.password("password")
					.role(AGENT)
					.build();
			System.out.println("Manager token: " + service.register(manager).getAccessToken());

		};*/

}
