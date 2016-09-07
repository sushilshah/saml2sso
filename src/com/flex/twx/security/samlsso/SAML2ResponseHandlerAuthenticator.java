package com.flex.twx.security.samlsso;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.thingworx.metadata.annotations.ThingworxConfigurationTableDefinitions;
import com.thingworx.security.authentication.AuthenticatorException;
import com.thingworx.security.authentication.CustomAuthenticator;
import com.thingworx.common.RESTAPIConstants;
import com.thingworx.common.RESTAPIConstants.Method;
import com.thingworx.common.RESTAPIConstants.StatusCode;
import com.thingworx.common.exceptions.InvalidRequestException;
//import com.thingworx.common.utils.StringUtilities;
import com.thingworx.logging.LogUtilities;
import com.thingworx.metadata.annotations.ThingworxConfigurationTableDefinitions;
import com.thingworx.security.authentication.AuthenticationUtilities;
import com.thingworx.security.authentication.AuthenticatorException;
import com.thingworx.security.authentication.CustomAuthenticator;
import com.thingworx.things.security.SecurityMonitorThing;
import com.thingworx.types.collections.ConfigurationTableCollection;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;

@ThingworxConfigurationTableDefinitions(tables={@com.thingworx.metadata.annotations.ThingworxConfigurationTableDefinition(name="AuthenticatorConfiguration", description="Authenticator Configuration", isMultiRow=false, dataShape=@com.thingworx.metadata.annotations.ThingworxDataShapeDefinition(fields={@com.thingworx.metadata.annotations.ThingworxFieldDefinition(name="ACSURL", description="The Thingworx Assertion Consumer Service URL for which this authenticator will handle/process the SAML2 Responses, should be the same as the ACS URL in the SAML2 Request Authenticator", baseType="STRING", aspects={"defaultValue:/Thingworx/Home"})}))})
public class SAML2ResponseHandlerAuthenticator extends CustomAuthenticator {
	  public static final Logger logger = LogUtilities.getInstance().getApplicationLogger(SAML2ResponseHandlerAuthenticator.class);
	  private static final String INVALID_AUTHENTICATION_MESSAGE = "Authentication failed.  Please make sure the credentials are correct.";
	  private static final String CONFIGURATION_TABLENAME = "AuthenticatorConfiguration";
	  private static final String CONFIGURATION_KEYNAME_ACSURL = "ACSURL";

	public SAML2ResponseHandlerAuthenticator() {
		// TODO Auto-generated constructor stub
		setPriority(1);
	}

	@Override
	public void authenticate(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
			throws AuthenticatorException {
	    SampleSAML2Utilities.SampleSAML2ResponseData responseData = null;
	    String relayState = null;
	    try
	    {
	      responseData = SampleSAML2Utilities.getSAMLResponseData(httpRequest);
	      relayState = SampleSAML2Utilities.getRelayState(httpRequest);
	      if (SampleSAML2Utilities.isRelayStateValid(relayState))
	      {
	        AuthenticationUtilities.validateEnabledThingworxUser(responseData.userName);
	        setCredentials(responseData.userName);
	        AuthenticationUtilities.getSecurityMonitorThing().fireSuccessfulLoginEvent(responseData.userName, "");
	        SampleSAML2Utilities.deleteNewRelayState(relayState);
	      }
	      else
	      {
	        logger.error("Invalid relay state received: " + relayState);
	        throw new Exception("Invalid request received");
	      }
	    }
	    catch (Exception eValidate)
	    {
	      try
	      {
	        AuthenticationUtilities.getSecurityMonitorThing().fireFailedLoginEvent(responseData.userName, eValidate.getMessage());
	      }
	      catch (Exception e)
	      {
	        logger.error("Unable to fire failed login event: " + e.getMessage());
	      }
	      throw new AuthenticatorException(eValidate);
	    }


	}

	@Override
	public void issueAuthenticationChallenge(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
			throws AuthenticatorException {
	    InvalidRequestException ire = new InvalidRequestException("Authentication failed.  Please make sure the credentials are correct.", RESTAPIConstants.StatusCode.STATUS_UNAUTHORIZED);
	    throw new AuthenticatorException(ire);

	}

	@Override
	public boolean matchesAuthRequest(HttpServletRequest httpRequest) throws AuthenticatorException {
	    boolean matches = false;
	    
	    String acsURL = (String)getConfigurationData().getValue("AuthenticatorConfiguration", "ACSURL");
	    
	    String uri = httpRequest.getRequestURI();
	    if (StringUtilities.isNonEmpty(uri)) {
	      if (uri.equalsIgnoreCase(acsURL))
	      {
	        String sMethod = httpRequest.getMethod();
	        RESTAPIConstants.Method method = RESTAPIConstants.getMethod(sMethod);
	        if ((method != null) && (method == RESTAPIConstants.Method.POST))
	        {
	          String contentType = httpRequest.getContentType();
	          if (contentType.equalsIgnoreCase("application/x-www-form-urlencoded"))
	          {
	            String samlResponse = SampleSAML2Utilities.getEncodedSAMLResponse(httpRequest);
	            if (samlResponse != null) {
	              matches = true;
	            }
	          }
	        }
	      }
	    }
	    return matches;
	}

}
