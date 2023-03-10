# token-java
Token JWT - JAVA

## Codigos
---------------------------------------------------------------------------------------------
### pom.xml
```
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>2.1.1.RELEASE</version>
		<relativePath /> <!-- lookup parent from repository -->
	</parent>
	<groupId>com.wlopera.jwt</groupId>
	<artifactId>token-java</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<name>token-java</name>
	<description>Proyecto Spring Boot - JWT</description>
	<properties>
		<java.version>11</java.version>
	</properties>
	<dependencies>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-thymeleaf</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
		</dependency>
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt</artifactId>
			<version>0.9.1</version>
		</dependency>
		<!-- API, java.xml.bind module -->
		<dependency>
			<groupId>jakarta.xml.bind</groupId>
			<artifactId>jakarta.xml.bind-api</artifactId>
			<version>2.3.2</version>
		</dependency>
		<!-- Runtime, com.sun.xml.bind module -->
		<dependency>
			<groupId>org.glassfish.jaxb</groupId>
			<artifactId>jaxb-runtime</artifactId>
			<version>2.3.2</version>
		</dependency>
	</dependencies>
	<build>
		<plugins>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
			</plugin>
		</plugins>
	</build>
</project>
```
### TokenApplication.xml
```
package com.wloper.jwt.tokenjava;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.wloper.jwt.tokenjava.filter.JWTAuthorizationFilter;

@SpringBootApplication
public class TokenApplication {

	public static void main(String[] args) {
		SpringApplication.run(TokenApplication.class, args);
	}
	
	@EnableWebSecurity
	@Configuration
	class WebSecurityConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.csrf().disable()
				.addFilterAfter(new JWTAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class)
				.authorizeRequests()
				.antMatchers(HttpMethod.GET, "/init").permitAll()
				.antMatchers("/login").permitAll()
				.anyRequest().authenticated();
		}
	}
}

```

### User.xml
```
package com.wloper.jwt.tokenjava.model;

public class User {

	private String name;
	private String password;
	private String token;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
	
	

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	@Override
	public String toString() {
		return "User [name=" + name + ", password=***, token=" + token + "]";
	}
}
```

### JWTAuthorizationFilter.xml
```
package com.wloper.jwt.tokenjava.filter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;

public class JWTAuthorizationFilter extends OncePerRequestFilter {
	private final String HEADER = "Authorization";
	private final String PREFIX = "Bearer ";
	private final String SECRET = "mySecretKey";

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		try {
			if (existeJWTToken(request, response)) {
				Claims claims = validateToken(request);
				if (claims.get("authorities") != null) {
					setUpSpringAuthentication(claims);
				} else {
					SecurityContextHolder.clearContext();
				}
			} else {
				SecurityContextHolder.clearContext();
			}
			chain.doFilter(request, response);
		} catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException e) {
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			((HttpServletResponse) response).sendError(HttpServletResponse.SC_FORBIDDEN, e.getMessage());
			return;
		}
	}

	private Claims validateToken(HttpServletRequest request) {
		String jwtToken = request.getHeader(HEADER).replace(PREFIX, "");
		return Jwts.parser().setSigningKey(SECRET.getBytes()).parseClaimsJws(jwtToken).getBody();
	}

	/**
	 * Metodo para autenticarnos dentro del flujo de Spring
	 * 
	 * @param claims
	 */
	private void setUpSpringAuthentication(Claims claims) {
		@SuppressWarnings("unchecked")
		List<String> authorities = (List<String>) claims.get("authorities");

		UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(claims.getSubject(), null,
				authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
		SecurityContextHolder.getContext().setAuthentication(auth);

	}

	private boolean existeJWTToken(HttpServletRequest request, HttpServletResponse res) {
		String authenticationHeader = request.getHeader(HEADER);
		if (authenticationHeader == null || !authenticationHeader.startsWith(PREFIX))
			return false;
		return true;
	}
}
```

### TokenController.xml
```
package com.wloper.jwt.tokenjava.controller;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import com.wloper.jwt.tokenjava.model.User;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Controller
public class TokenController {

	@GetMapping("/init")
	public String init(User user) {
		System.out.println("Iniciar consulta de login...");
		return "login";
	}

	@PostMapping("/login")
	public String login(@Validated User user, BindingResult result, Model model) {
		System.out.println("User: " + user);

		SimpleDateFormat format = new SimpleDateFormat("DD/mm/YYYY HH:mm:ss");
		String date = format.format(new Date());
		
		String token = getJWTToken(user.getName(), date);
		user.setToken(token);
		System.out.println("Token: " + token);
		model.addAttribute("user", user);
		return "user_conected";
	}

	private String getJWTToken(String username, String date) {
		String secretKey = "mySecretKey";
		List<GrantedAuthority> grantedAuthorities = AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER");

		System.out.println("usernaqme: " + username);
		String token = Jwts.builder().setId("softtekJWT").setSubject(username)
				.claim("autorizaciones",
						grantedAuthorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
				.claim("Fecha", date).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 600000))
				.signWith(SignatureAlgorithm.HS512, secretKey.getBytes()).compact();

		return "Bearer " + token;
	}
}

```

### login.html
```
<html xmlns:th="http://www.thymeleaf.org">

<head>
	<meta charset="UTF-8">
	<title>JWT-login</title>
	<link th:href="@{/styles/style.css}" rel="stylesheet" />
</head>
<div th:switch="${customers}" class="container">
	<div>
		<form action="#" th:action="@{/login}" th:object="${user}" method="post" class="form">
			<label for="name">Nombre</label>
			<input type="text" th:field="*{name}" id="name" placeholder="Nombre">
			<span th:if="${#fields.hasErrors('name')}" th:errors="*{name}"></span>

			<label for="password">Clave</label>
			<input type="password" th:field="*{password}" id="name" placeholder="Clave">
			<span th:if="${#fields.hasErrors('password')}" th:errors="*{password}"></span>

			<input type="submit" value="Conectarse">
		</form>
	</div>
</div>

</html>
```

### user_conected.html
```
<html xmlns:th="http://www.thymeleaf.org">

<head>
	<meta charset="UTF-8">
	<title>JWT-login</title>
	<link th:href="@{/styles/style.css}" rel="stylesheet" />
</head>
<div th:switch="${user}" class="container">
	<div>
		<form class="form">
			<p>Cliente Conectado: <span th:text="${user.name}"></span>
			<p>Token: <span th:text="${user.token}"></span>
		</form>
	</div>
</div>

</html>
```
## Salida 
 * Levantar servidor.

 * http://localhost:8080/init

![Captura](https://user-images.githubusercontent.com/7141537/224443365-092475d0-312b-4f95-b29c-80d14bcb6488.PNG)

 * http://localhost:8080/login

![Captura1](https://user-images.githubusercontent.com/7141537/224443366-ae0a44f7-9d5d-4aac-8d0d-fc50bca2b7de.PNG)

* Probar token

![Captura2](https://user-images.githubusercontent.com/7141537/224443362-e2e1f85b-7137-4fce-9def-4544441d7f87.PNG)

