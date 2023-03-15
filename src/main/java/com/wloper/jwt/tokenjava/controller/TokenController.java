package com.wloper.jwt.tokenjava.controller;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
	
	@GetMapping("/data")
	public String getData(Model model) {
		System.out.println("Consultar datos...");
		
		Map<String, String> data = new HashMap<>();
		data.put("Pais", "Venezuela");
		data.put("Capital", "Caracas");
		data.put("Lenguaje", "Español");
		data.put("Moneda", "Bolívar");
		
		model.addAttribute("data", data);
		
		return "data";
	}


	private String getJWTToken(String username, String date) {
		String secretKey = "mySecretKey";
		List<GrantedAuthority> grantedAuthorities = AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER");

		System.out.println("usernaqme: " + username);
		String token = Jwts.builder().setId("softtekJWT").setSubject(username)
				.claim("authorities",
						grantedAuthorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
				.claim("Fecha", date).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 600000))
				.signWith(SignatureAlgorithm.HS512, secretKey.getBytes()).compact();

		return "Bearer " + token;
	}
}
