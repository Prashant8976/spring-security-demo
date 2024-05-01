package com.example.security.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

	@Bean
	public UserDetailsService detailsService() {
		UserDetails admin = User.withUsername("test").password(encoder().encode("123")).roles("ADMIN").build();
		UserDetails user = User.withUsername("t1").password(encoder().encode("123")).roles("USER").build();
		return new InMemoryUserDetailsManager(admin, user);
	}
	
	/*
	 * @Bean public SecurityFilterChain filterChain(HttpSecurity httpSecurity)
	 * throws Exception {
	 * 
	 * httpSecurity .csrf(csrf->csrf.disable()) .authorizeHttpRequests(t ->
	 * t.anyRequest().fullyAuthenticated()) .formLogin(Customizer.withDefaults());
	 * return httpSecurity.build(); }
	 */
	/*
	 * @Bean public SecurityFilterChain filterChain(HttpSecurity httpSecurity)
	 * throws Exception {
	 * 
	 * httpSecurity .csrf(csrf->csrf.disable()) .authorizeHttpRequests(t ->
	 * t.requestMatchers("/admin/**")
	 * .fullyAuthenticated().anyRequest().permitAll())
	 * .formLogin(Customizer.withDefaults()); return httpSecurity.build(); }
	 */
	
	/*
	 * @Bean public SecurityFilterChain filterChain(HttpSecurity httpSecurity)
	 * throws Exception { httpSecurity .csrf(csrf -> csrf.disable())
	 * .authorizeHttpRequests(t -> t.requestMatchers("/api/**").authenticated()).oa
	 * return httpSecurity.build(); }A
	 */	
	@Bean
	public PasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}
}
