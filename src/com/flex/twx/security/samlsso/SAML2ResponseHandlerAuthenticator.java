package com.flex.twx.security.samlsso;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;

import com.thingworx.common.RESTAPIConstants;
import com.thingworx.common.exceptions.InvalidRequestException;
//import com.thingworx.common.utils.StringUtilities;
import com.thingworx.logging.LogUtilities;
import com.thingworx.metadata.annotations.ThingworxConfigurationTableDefinitions;
import com.thingworx.security.authentication.AuthenticationUtilities;
import com.thingworx.security.authentication.AuthenticatorException;
import com.thingworx.security.authentication.CustomAuthenticator;

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
	    System.out.println("*** authenticate saml  response1 "  );
	    try
	    {
	    	System.out.println("*** authenticate saml  response1.1 before getSAMLResponseData "  );
	      responseData = SampleSAML2Utilities.getSAMLResponseData(httpRequest);
	      System.out.println("*** authenticate saml  response2 " + responseData);
	      //after this line it is going to **matchesAuthRequest return values :true TODO trace it
	      relayState = SampleSAML2Utilities.getRelayState(httpRequest);
	      System.out.println("Validating user : " + responseData.userName);
	      System.out.println("*** httpRequest : " + httpRequest.toString());
	      System.out.println("*** httpResponse : " + httpResponse.toString());
	      if (SampleSAML2Utilities.isRelayStateValid(relayState))
	      {
	    	logger.debug("Validating user : " + responseData.userName);
	    	System.out.println("Validating user : " + responseData.userName);
	        AuthenticationUtilities.validateEnabledThingworxUser(responseData.userName);
	        setCredentials(responseData.userName);
	        AuthenticationUtilities.getSecurityMonitorThing().fireSuccessfulLoginEvent(responseData.userName, "");
	        logger.debug("saml relay state : " + relayState);
	        System.out.println("saml relay state : " + relayState);
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
	    	System.out.println("Exception: " + eValidate.getMessage());
	    	System.out.println(eValidate);
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
	    
	    //String acsURL = (String)getConfigurationData().getValue("AuthenticatorConfiguration", "ACSURL");
	    String acsURL = null;
		try {
			//acsURL = (String) getConfigurationTable("AuthenticatorConfiguration").getFirstRow().getValue("ACSURL");
			//acsURL = "http://localhost:8080/Thingworx/Home";
			acsURL = "/Thingworx/Home";
			logger.debug("Using ACS Url as" + acsURL);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			logger.error(e.getMessage());
			e.printStackTrace();
		}
	    String uri = httpRequest.getRequestURI();
	    System.out.println("*** httpRequest.getRequestURI() : " + uri );
	    if (uri != null && uri.length() > 0) {
	      if (uri.equalsIgnoreCase(acsURL))
	      {
	        String sMethod = httpRequest.getMethod();
	        RESTAPIConstants.Method method = RESTAPIConstants.getMethod(sMethod);
	        System.out.println("*** http method " + method + " :: " + RESTAPIConstants.Method.POST);
	        if ((method != null) && (method == RESTAPIConstants.Method.POST))
	        {
	          String contentType = httpRequest.getContentType();
	          System.out.println("***Content type : " + contentType);
	          if (contentType.equalsIgnoreCase("application/x-www-form-urlencoded"))
	          {
	        	 logger.debug("Inside if cond, content type : application form urlencoded" );
	            String samlResponse = SampleSAML2Utilities.getEncodedSAMLResponse(httpRequest);
	            System.out.println("***samlResponse : " );
	            if (samlResponse != null) {
	            	System.out.println("***samlResponse :true " );
	              matches = true;
	            }
	          }
	        }
	      }
	    }
	   /* boolean matches = true;
	    try
	    {
	      String appKey = httpRequest.getParameter("appKey");
	      if ((appKey != null) && (!appKey.isEmpty())) {
	        matches = false;
	      }
	    }
	    catch (Throwable t)
	    {
	      throw new AuthenticatorException(t);
	    }*/
	    
	    logger.debug(" matchesAuthRequest saml response return val : " + matches);
	    System.out.println(" matchesAuthRequest saml response return val : " + matches);
	    return matches;
	}

}
