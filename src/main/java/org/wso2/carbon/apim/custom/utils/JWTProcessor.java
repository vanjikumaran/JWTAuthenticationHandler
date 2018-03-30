/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.apim.custom.utils;

import org.apache.axiom.util.base64.Base64Utils;

import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;

public class JWTProcessor {

	String signAlgorithm;
	String assersion;
	String signature;
 
	//gets jwt token and separate into parts
	public JWTProcessor(String jwtToken) {

		if (jwtToken != null) {
	    	String[] jwtParts = jwtToken.split("\\.");
    		if (jwtParts.length == 3) {
    			signAlgorithm = jwtParts[0];
    			signAlgorithm = getAlgorithmFormJWT(signAlgorithm);
    			assersion = jwtParts[0] + "." + jwtParts[1]; //add with a dot;
    	    	signature = jwtParts[2];
    		}
    	}
	}
	
	public String getSignAlgorithm() {
		return signAlgorithm;
	}
	
	public String getAssersion() {
		return assersion;
	}

	public String getSignature() {
		return signature;
	}
	
	private String getAlgorithmFormJWT(String algorithm) throws JsonParseException {
		JsonParser parser = new JsonParser();
		byte[] decoded = Base64Utils.decode(algorithm);
		String jwtHeader = new String(decoded, java.nio.charset.Charset.forName("UTF-8"));
		JsonElement header = parser.parse(jwtHeader);
		algorithm = header.getAsJsonObject().get("alg").getAsString();
		return algorithm;
	}
	
	public String getDecodedAssersion(String assersion) throws JsonParseException {
		String[] jwtParts = assersion.split("\\.");
		byte[] decoded = Base64Utils.decode(jwtParts[1]);
		String jwtBody = new String(decoded, java.nio.charset.Charset.forName("UTF-8"));
		return jwtBody;
	}
	 
	
}
