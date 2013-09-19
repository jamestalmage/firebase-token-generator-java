package com.firebase.security.token;

import java.nio.charset.Charset;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.commons.codec.binary.Base64;

/**
 * JWT encoder.
 * 
 * @author vikrum
 *
 */
public class JWTEncoder {
	
	private static final String TOKEN_SEP = ".";
	private static final Charset UTF8_CHARSET = Charset.forName("UTF-8");
	private static final String HMAC_256 = "HmacSHA256";
	
	/**
	 * Encode and sign a set of claims.
	 * 
	 * @param claims
	 * @param secret
	 * @return
	 */
	public static String encode(ObjectNode claims, String secret) {
		
		String encodedHeader = getCommonHeader();
		String encodedClaims = encodeJson(claims);
		
		String secureBits = new StringBuilder(encodedHeader).append(TOKEN_SEP).append(encodedClaims).toString();
		
		String sig = sign(secret, secureBits);
		
		return new StringBuilder(secureBits).append(TOKEN_SEP).append(sig).toString();
	}
	
	private static String sign(String secret, String secureBits) {
		String result = null;
		try {
			Mac sha256_HMAC = Mac.getInstance(HMAC_256);
			SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(UTF8_CHARSET), HMAC_256);
			sha256_HMAC.init(secret_key);
			byte sig[] = sha256_HMAC.doFinal(secureBits.getBytes(UTF8_CHARSET));
			result = Base64.encodeBase64URLSafeString(sig);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return result;
	}

	private static String getCommonHeader() {
    ObjectNode headerJson = new ObjectNode(JsonNodeFactory.instance);
		try {
			headerJson.put("typ", "JWT");
			headerJson.put("alg", "HS256");
		} catch (Exception e) {
			e.printStackTrace();
		}
		return encodeJson(headerJson);
	}
	
	private static String encodeJson(ObjectNode jsonData) {
		return Base64.encodeBase64URLSafeString(jsonData.toString().getBytes(UTF8_CHARSET));
	}

}
