package com.firebase.security.token;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.Date;

/**
 * Firebase JWT token generator.
 * 
 * @author vikrum
 *
 */
public class TokenGenerator {
	
	private static final int TOKEN_VERSION = 0;
	
	private String firebaseSecret;

	/**
	 * Default constructor given a Firebase secret.
	 * 
	 * @param firebaseSecret
	 */
	public TokenGenerator(String firebaseSecret) {
		super();
		this.firebaseSecret = firebaseSecret;
	}
	
	/**
	 * Create a token for the given object.
	 * 
	 * @param data
	 * @return
	 */
	public String createToken(ObjectNode data) {
		return createToken(data, new TokenOptions());
	}
	
	/**
	 * Create a token for the given object and options.
	 * 
	 * @param data
	 * @param options
	 * @return
	 */
	public String createToken(ObjectNode data, TokenOptions options) {
    ObjectNode claims = new ObjectNode(JsonNodeFactory.instance);

		try {
			claims.put("v", TOKEN_VERSION);
			claims.put("iat", new Date().getTime() / 1000);
			
			if(data != null && data.size() > 0) {
				claims.put("d", data);
			}
			
			// Handle options
			if(options != null) {
				if(options.getExpires() != null) {
					claims.put("exp", options.getExpires().getTime() / 1000);
				}
				
				if(options.getNotBefore() != null) {
					claims.put("nbf", options.getNotBefore().getTime() / 1000);
				}
				
				// Only add these claims if they're true to avoid sending them over the wire when false.
				if(options.isAdmin()) {
					claims.put("admin", options.isAdmin());
				}
				
				if(options.isDebug()) {
					claims.put("debug", options.isDebug());	
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return computeToken(claims);
	}

	private String computeToken(ObjectNode claims) {
		return JWTEncoder.encode(claims, firebaseSecret);
	}
}
