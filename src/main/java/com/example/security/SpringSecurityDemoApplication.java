package com.example.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
public class SpringSecurityDemoApplication {

	public static void main(String[] args) {
		System.out.print("test1");
		SpringApplication.run(SpringSecurityDemoApplication.class, args);
	}

}
