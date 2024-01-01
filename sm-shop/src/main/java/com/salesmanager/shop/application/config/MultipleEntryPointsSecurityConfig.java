package com.salesmanager.shop.application.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.salesmanager.shop.admin.security.UserAuthenticationSuccessHandler;
import com.salesmanager.shop.admin.security.WebUserServices;
import com.salesmanager.shop.store.controller.customer.facade.CustomerFacade;
import com.salesmanager.shop.store.security.AuthenticationTokenFilter;
import com.salesmanager.shop.store.security.ServicesAuthenticationSuccessHandler;
import com.salesmanager.shop.store.security.admin.JWTAdminAuthenticationProvider;
import com.salesmanager.shop.store.security.admin.JWTAdminServicesImpl;
import com.salesmanager.shop.store.security.customer.JWTCustomerAuthenticationProvider;
import com.salesmanager.shop.store.security.services.CredentialsService;
import com.salesmanager.shop.store.security.services.CredentialsServiceImpl;

/**
 * Main entry point for security - admin - customer - auth - private - services
 * 
 * @author dur9213
 *
 */
@Configuration
@EnableWebSecurity
public class MultipleEntryPointsSecurityConfig {

	private static final String API_VERSION = "/api/v*";

	@Bean
	public AuthenticationTokenFilter authenticationTokenFilter() {
		return new AuthenticationTokenFilter();
	}

	@Bean
	public CredentialsService credentialsService() {
		return new CredentialsServiceImpl();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public UserAuthenticationSuccessHandler userAuthenticationSuccessHandler() {
		return new UserAuthenticationSuccessHandler();
	}

	@Bean
	public ServicesAuthenticationSuccessHandler servicesAuthenticationSuccessHandler() {
		return new ServicesAuthenticationSuccessHandler();
	}

	@Bean
	public CustomerFacade customerFacade() {
		return new com.salesmanager.shop.store.controller.customer.facade.CustomerFacadeImpl();
	}

	/**
	 * shop / customer
	 * 
	 * @author dur9213
	 *
	 */
	@Configuration
	@Order(1)
	public static class CustomerConfigurationAdapter {

		// @Bean("customerAuthenticationManager")
		// public AuthenticationManager authenticationManagerBean() throws Exception {
		// return super.authenticationManagerBean();
		// }

		@Autowired
		private UserDetailsService customerDetailsService;

		public CustomerConfigurationAdapter() {
			super();
		}

		@Bean
		public WebSecurityCustomizer webSecurityCustomizer() {
			return (web) -> web.ignoring().requestMatchers("/", "/error", "/resources/**", "/static/**",
					"/services/public/**");
		}

		public void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.userDetailsService(customerDetailsService);
		}

		@Bean
		public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			http.csrf((csrf) -> csrf.disable())
					.authorizeHttpRequests(
							(authorize) -> authorize.requestMatchers("/shop/").permitAll()
									.requestMatchers("/shop/**").permitAll()
									.requestMatchers("/shop/customer/logon*").permitAll()
									.requestMatchers("/shop/customer/registration*").permitAll()
									.requestMatchers("/shop/customer/logout*").permitAll()
									.requestMatchers("/shop/customer/customLogon*").permitAll()
									.requestMatchers("/shop/customer/denied*").permitAll()
									.requestMatchers("/shop/customer/**").hasRole("AUTH_CUSTOMER")
									.anyRequest().authenticated()

					).exceptionHandling(exception -> exception
							.authenticationEntryPoint(shopAuthenticationEntryPoint()))
					.sessionManagement(session -> session
							.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
			return http.build();
		}

		@Bean
		public AuthenticationEntryPoint shopAuthenticationEntryPoint() {
			BasicAuthenticationEntryPoint entryPoint = new BasicAuthenticationEntryPoint();
			entryPoint.setRealmName("shop-realm");
			return entryPoint;
		}

	}

	/**
	 * services api v0
	 * 
	 * @author dur9213
	 * @deprecated
	 *
	 */
	@Configuration
	@Order(2)
	public static class ServicesApiConfigurationAdapter {

		@Autowired
		private WebUserServices userDetailsService;

		@Autowired
		private ServicesAuthenticationSuccessHandler servicesAuthenticationSuccessHandler;

		public ServicesApiConfigurationAdapter() {
			super();
		}


		public void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.userDetailsService(userDetailsService);
		}

		@Bean
		public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			http.csrf((csrf) -> csrf.disable())
					.authorizeHttpRequests(
							(authorize) -> authorize
									.requestMatchers("/services/public/**").permitAll()
									.requestMatchers("/services/private/**").hasRole("AUTH")
									.anyRequest().authenticated()

					).exceptionHandling(exception -> exception
							.authenticationEntryPoint(servicesAuthenticationEntryPoint()))
					.sessionManagement(session -> session
							.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
			return http.build();
		}

		@Bean
		public AuthenticationEntryPoint servicesAuthenticationEntryPoint() {
			BasicAuthenticationEntryPoint entryPoint = new BasicAuthenticationEntryPoint();
			entryPoint.setRealmName("rest-customer-realm");
			return entryPoint;
		}

	}

	/**
	 * api - private
	 * 
	 * @author dur9213
	 *
	 */
	@Configuration
	@Order(5)
	public static class UserApiConfigurationAdapter {

		@Autowired
		private AuthenticationTokenFilter authenticationTokenFilter;

		@Autowired
		JWTAdminServicesImpl jwtUserDetailsService;

		public UserApiConfigurationAdapter() {
			super();
		}

		public void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.userDetailsService(jwtUserDetailsService);
		}

		@Bean
		public WebSecurityCustomizer webSecurityCustomizer() {
			return (web) -> web.ignoring().requestMatchers("/swagger-ui.html");
		}

		@Bean
		public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			http.csrf((csrf) -> csrf.disable())
					.authorizeHttpRequests(
							(authorize) -> authorize
									.requestMatchers(API_VERSION + "/private/**").permitAll()
									.requestMatchers(API_VERSION + "/private/login*").permitAll()
									.requestMatchers(API_VERSION + "/private/refresh").permitAll()
									.requestMatchers(HttpMethod.OPTIONS, API_VERSION + "/private/**").permitAll()
									.requestMatchers(API_VERSION + "/private/**").hasRole("AUTH")
									.anyRequest().authenticated()

					).exceptionHandling(exception -> exception
							.authenticationEntryPoint(apiAdminAuthenticationEntryPoint()))
					.sessionManagement(session -> session
							.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

			http.addFilterAfter(authenticationTokenFilter, BasicAuthenticationFilter.class);
			return http.build();
		}

		@Bean
		public AuthenticationProvider authenticationProvider() {
			JWTAdminAuthenticationProvider provider = new JWTAdminAuthenticationProvider();
			provider.setUserDetailsService(jwtUserDetailsService);
			return provider;
		}

		@Bean
		public AuthenticationEntryPoint apiAdminAuthenticationEntryPoint() {
			BasicAuthenticationEntryPoint entryPoint = new BasicAuthenticationEntryPoint();
			entryPoint.setRealmName("api-admin-realm");
			return entryPoint;
		}

	}

	/**
	 * customer api
	 * 
	 * @author dur9213
	 *
	 */
	@Configuration
	@Order(6)
	public static class CustomeApiConfigurationAdapter {

		@Autowired
		private AuthenticationTokenFilter authenticationTokenFilter;

		@Autowired
		private UserDetailsService jwtCustomerDetailsService;

		public CustomeApiConfigurationAdapter() {
			super();
		}

		public void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.userDetailsService(jwtCustomerDetailsService);
		}

		@Bean
		public WebSecurityCustomizer webSecurityCustomizer() {
			return (web) -> web.ignoring().requestMatchers("/swagger-ui.html");
		}

		@Bean
		public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			http.csrf((csrf) -> csrf.disable())
					.authorizeHttpRequests(
							(authorize) -> authorize
									.requestMatchers(API_VERSION + "/auth/refresh").permitAll()
									.requestMatchers(API_VERSION + "/auth/login").permitAll()
									.requestMatchers(API_VERSION + "/auth/register").permitAll()
									.requestMatchers(HttpMethod.OPTIONS, API_VERSION + "/auth/**").permitAll()
									.requestMatchers(API_VERSION + "/auth/**")
									.hasRole("AUTH_CUSTOMER").anyRequest().authenticated()
									.anyRequest().authenticated()

					).exceptionHandling(exception -> exception
							.authenticationEntryPoint(apiCustomerAuthenticationEntryPoint()))
					.sessionManagement(session -> session
							.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

			http.addFilterAfter(authenticationTokenFilter, BasicAuthenticationFilter.class);
			return http.build();
		}

		@Bean
		public AuthenticationProvider authenticationProvider() {
			JWTCustomerAuthenticationProvider provider = new JWTCustomerAuthenticationProvider();
			provider.setUserDetailsService(jwtCustomerDetailsService);
			return provider;
		}

		@Bean
		public AuthenticationEntryPoint apiCustomerAuthenticationEntryPoint() {
			BasicAuthenticationEntryPoint entryPoint = new BasicAuthenticationEntryPoint();
			entryPoint.setRealmName("api-customer-realm");
			return entryPoint;
		}

	}

}
