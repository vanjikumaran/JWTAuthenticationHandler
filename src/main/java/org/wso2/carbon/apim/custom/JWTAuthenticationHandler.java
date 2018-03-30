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

package org.wso2.carbon.apim.custom;

import org.apache.axis2.Constants;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.rest.AbstractHandler;
import org.apache.synapse.rest.RESTConstants;
import org.wso2.carbon.apim.custom.dto.JWTAssersion;
import org.wso2.carbon.apim.custom.utils.JWTUtil;
import org.wso2.carbon.apim.custom.utils.JWTProcessor;
import org.wso2.carbon.apimgt.gateway.APIMgtGatewayConstants;
import org.wso2.carbon.apimgt.gateway.handlers.security.APIKeyValidator;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityException;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityUtils;
import org.wso2.carbon.apimgt.gateway.handlers.security.AuthenticationContext;
import org.wso2.carbon.apimgt.gateway.handlers.security.ResourceNotFoundException;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.dto.VerbInfoDTO;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;



import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JWTAuthenticationHandler extends AbstractHandler {

    private static final Log log = LogFactory.getLog(JWTAuthenticationHandler.class);
    //properties read from handler configuration
	private String keystorePath;
    private String keystorePassword;
    private String keyAlias;
    
    public String getKeystorePath() {
		return keystorePath;
	}

	public void setKeystorePath(String keystorePath) {
		this.keystorePath = keystorePath;
	}

	public String getKeystorePassword() {
		return keystorePassword;
	}

	public void setKeystorePassword(String keystorePassword) {
		this.keystorePassword = keystorePassword;
	}

	public String getKeyAlias() {
		return keyAlias;
	}

	public void setKeyAlias(String keyAlias) {
		this.keyAlias = keyAlias;
	}

    public boolean handleRequest(MessageContext messageContext) {
    	
    	log.debug("Custom JWT Authentication Handler Engaged in Request Path");
        String jwtToken = JWTUtil.extractJWTToken(messageContext);
        log.debug(" jwtToken = " + jwtToken);
	    AuthenticationContext authContext = new AuthenticationContext();

    	if (StringUtils.isNotEmpty(jwtToken)) {
    		log.info("JWT header is present therefore validating jwt signature ");
    		JWTProcessor processor = new JWTProcessor(jwtToken);
    		JWTAssersion jwt = JWTUtil.getAssersion(processor.getDecodedAssersion(processor.getAssersion()));
    		boolean signatureValid = JWTUtil.validateJWTSignature(jwtToken, keystorePath, keystorePassword, keyAlias);

    		log.debug("signatureValid="+ signatureValid);

			if (!signatureValid) {
				return false;
			}
			//If the signature valid obtain the meta data.

        	String endUser = jwt.getEnduser();
        	String subscriber = jwt.getSubscriber();
        	String applicationName = jwt.getApplicationName();
        	String applicationId = jwt.getApplicationId();
        	String keyType = jwt.getKeyType();
			String tier = jwt.getTier();
			String applicationTier = jwt.getApplicationTier();

		    //set all the properties required for other handlers in here which we extracted from the jwt
		    authContext.setAuthenticated(true);
		    authContext.setApplicationId(applicationId);
		    authContext.setApplicationName(applicationName);
		    authContext.setKeyType(keyType);
		    authContext.setStopOnQuotaReach(true);
		    authContext.setTier(tier);
		    authContext.setSubscriber(subscriber);
		    authContext.setApplicationTier(applicationTier);
		    authenticateInfo(messageContext, authContext);
		    setAPIParametersToMessageContext(messageContext);
        	log.debug("endUser= " + endUser + " subscriber= " + subscriber + " applicationName= " + applicationName + " keyType= " + keyType);
    	}
	    return true;
    }

    public boolean handleResponse(MessageContext messageContext) {
        return true;
    }

	private void authenticateInfo(MessageContext messageContext, AuthenticationContext authContext) {
		String clientIP = null;

		org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext)
				.getAxis2MessageContext();
		TreeMap<String, String> transportHeaderMap = (TreeMap<String, String>) axis2MessageContext
				.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

		if (transportHeaderMap != null) {
			clientIP = transportHeaderMap.get(APIMgtGatewayConstants.X_FORWARDED_FOR);
		}

		//Setting IP of the client
		if (StringUtils.isNotEmpty(clientIP)) {
			if (clientIP.indexOf(",") > 0) {
				clientIP = clientIP.substring(0, clientIP.indexOf(","));
			}
		} else {
			clientIP = (String) axis2MessageContext.getProperty(org.apache.axis2.context.MessageContext.REMOTE_ADDR);
		}

		authContext.setAuthenticated(true);

		//Can modify to support scopes based throttle policy selection
		authContext.setStopOnQuotaReach(true);
		authContext.setApiKey(clientIP);
		authContext.setCallerToken(null);
		authContext.setConsumerKey(null);
		APISecurityUtils.setAuthenticationContext(messageContext, authContext, "X-JWT-Assertion");
	}

	private void setAPIParametersToMessageContext(MessageContext messageContext) {

		AuthenticationContext authContext = APISecurityUtils.getAuthenticationContext(messageContext);
		org.apache.axis2.context.MessageContext axis2MsgContext = ((Axis2MessageContext) messageContext)
				.getAxis2MessageContext();

		String consumerKey = "";
		String username = "";
		String applicationName = "";
		String applicationId = "";
		if (authContext != null) {
			consumerKey = authContext.getConsumerKey();
			username = authContext.getUsername();
			applicationName = authContext.getApplicationName();
			applicationId = authContext.getApplicationId();
		}

		String context = (String) messageContext.getProperty(RESTConstants.REST_API_CONTEXT);
		String apiVersion = (String) messageContext.getProperty(RESTConstants.SYNAPSE_REST_API);

		String apiPublisher = (String) messageContext.getProperty(APIMgtGatewayConstants.API_PUBLISHER);
		//if publisher is null,extract the publisher from the api_version
		if (apiPublisher == null) {
			int ind = apiVersion.indexOf("--");
			apiPublisher = apiVersion.substring(0, ind);
			if (apiPublisher.contains(APIConstants.EMAIL_DOMAIN_SEPARATOR_REPLACEMENT)) {
				apiPublisher = apiPublisher
						.replace(APIConstants.EMAIL_DOMAIN_SEPARATOR_REPLACEMENT, APIConstants.EMAIL_DOMAIN_SEPARATOR);
			}
		}
		int index = apiVersion.indexOf("--");

		if (index != -1) {
			apiVersion = apiVersion.substring(index + 2);
		}

		String api = apiVersion.split(":")[0];
		String version = (String) messageContext.getProperty(RESTConstants.SYNAPSE_REST_API_VERSION);
		String resource = extractResource(messageContext);
		String method = (String) (axis2MsgContext.getProperty(Constants.Configuration.HTTP_METHOD));
		String hostName = APIUtil.getHostAddress();

		messageContext.setProperty(APIMgtGatewayConstants.CONSUMER_KEY, consumerKey);
		messageContext.setProperty(APIMgtGatewayConstants.USER_ID, username);
		messageContext.setProperty(APIMgtGatewayConstants.CONTEXT, context);
		messageContext.setProperty(APIMgtGatewayConstants.API_VERSION, apiVersion);
		messageContext.setProperty(APIMgtGatewayConstants.API, api);
		messageContext.setProperty(APIMgtGatewayConstants.VERSION, version);
		messageContext.setProperty(APIMgtGatewayConstants.RESOURCE, resource);
		messageContext.setProperty(APIMgtGatewayConstants.HTTP_METHOD, method);
		messageContext.setProperty(APIMgtGatewayConstants.HOST_NAME, hostName);
		messageContext.setProperty(APIMgtGatewayConstants.API_PUBLISHER, apiPublisher);
		messageContext.setProperty(APIMgtGatewayConstants.APPLICATION_NAME, applicationName);
		messageContext.setProperty(APIMgtGatewayConstants.APPLICATION_ID, applicationId);


		APIKeyValidator validator = new APIKeyValidator(null);
		try {
			VerbInfoDTO verb = validator.findMatchingVerb(messageContext);
			if (verb != null) {
				messageContext.setProperty(APIConstants.VERB_INFO_DTO, verb);
			}
		} catch (ResourceNotFoundException e) {
			log.error("Could not find matching resource for request", e);
		} catch (APISecurityException e) {
			log.error("APISecurityException for request:", e);
		}
	}

	private String extractResource(MessageContext mc) {
		String resource = "/";
		Pattern pattern = Pattern.compile("^/.+?/.+?([/?].+)$");
		Matcher matcher = pattern.matcher((String) mc.getProperty(RESTConstants.REST_FULL_REQUEST_PATH));
		if (matcher.find()) {
			resource = matcher.group(1);
		}
		return resource;
	}

}