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
