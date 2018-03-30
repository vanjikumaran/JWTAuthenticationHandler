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

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.apim.custom.JWTSignatureValidator;
import org.wso2.carbon.apim.custom.dto.JWTAssersion;

public class JWTUtil {
	
	private static final Log log = LogFactory.getLog(JWTUtil.class);
	private static final String X_JWT_ASSERTION = "X-JWT-Assertion";


	public static boolean validateJWTSignature(String jwtToken, String keystorePath, String keystorePassword, String keyAlias)	{
		
		JWTProcessor processor = new JWTProcessor(jwtToken);
		String signAlgorithm = processor.getSignAlgorithm();
		String apimAssersion = processor.getAssersion();
    	String apimSignedJWT = processor.getSignature();

    	//If JWT configs are wrong return false
    	if (StringUtils.isEmpty(signAlgorithm) || StringUtils.isEmpty(apimAssersion) || StringUtils.isEmpty(apimSignedJWT)) {
    		log.error("Invalid JWT token");
    		return false;
    	}
    	
    	Boolean isValid = false;
        try {
        	
    	    Certificate cert = getCertificateFromKeystore(keystorePath, keystorePassword, keyAlias);
    	    
    	    JWTSignatureValidator validator = new JWTSignatureValidator(signAlgorithm, cert);
    	    
    	    isValid = validator.validateSignature(apimAssersion, apimSignedJWT);
			if (log.isDebugEnabled()) {
				log.debug("APIM Signature " +  isValid);
			} 
			if (!isValid) {
				log.error("APIM Signature Validation Failed");
			}
			
		} catch (Exception e) {
			log.error("Error occured while validating signature "+ e.getMessage());
		}
        
        return isValid;
	}

	
	private static Certificate getCertificateFromKeystore(String keystorePath, String keystorePassword, String keyAlias)
			throws KeyStoreException, IOException, NoSuchAlgorithmException,
			CertificateException {
		
		InputStream file = new FileInputStream(keystorePath); 
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		keystore.load(file, keystorePassword.toCharArray());
		Certificate cert = keystore.getCertificate(keyAlias);
		file.close();
		return cert;
	}

	public static JWTAssersion getAssersion(String assersion){
		JSONParser parser = new JSONParser();

		JWTAssersion jwt = new JWTAssersion();
		try {
			Object obj = parser.parse(assersion);
			JSONObject jsonObject = (JSONObject)obj;
			jwt.setSubscriber((String)jsonObject.get("http://wso2.org/claims/subscriber"));
			jwt.setApplicationId((String)jsonObject.get("http://wso2.org/claims/applicationid"));
			jwt.setApplicationName((String)jsonObject.get( "http://wso2.org/claims/applicationname"));
			jwt.setEnduser((String)jsonObject.get("http://wso2.org/claims/enduser"));
			jwt.setKeyType((String)jsonObject.get("http://wso2.org/claims/keytype"));
			jwt.setTier((String)jsonObject.get("http://wso2.org/claims/tier"));
			jwt.setApplicationTier((String)jsonObject.get("http://wso2.org/claims/applicationtier"));

			//long expiresIn = ((Long)jsonObject.get("expires_in")).intValue();
			//jwt.setExpiresIn(expiresIn);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		return jwt;
	}


	public static String extractJWTToken(MessageContext messageContext) {
		Map transportHeaders = (Map) ((Axis2MessageContext) messageContext).getAxis2MessageContext().
				getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
		String jwtToken = null;
		if (transportHeaders != null && transportHeaders.containsKey(X_JWT_ASSERTION)) {
			jwtToken = (String) transportHeaders.get(X_JWT_ASSERTION);
		}
		return jwtToken;
	}
}
