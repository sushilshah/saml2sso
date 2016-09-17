package com.flex.twx.security.samlsso;

import java.io.ByteArrayInputStream;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.opensaml.xml.util.Base64;
import org.slf4j.Logger;

import com.flex.twx.security.samlsso.SampleSAML2Utilities.SampleSAML2ResponseData;
import com.thingworx.common.RESTAPIConstants;
import com.thingworx.common.exceptions.InvalidRequestException;
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
	    SampleSAML2Utilities.SampleSAML2ResponseData responseData = new SampleSAML2ResponseData();;
	    String relayState = null;
	    System.out.println("*** authenticate saml  response1 "  );
	    try
	    {
	    	
	      //responseData = SampleSAML2Utilities.getSAMLResponseData(httpRequest);
	    	
	    	String responseMessage = httpRequest.getParameter("SAMLResponse").toString(); 
	    	System.out.println("####responseMessage");
	    	System.out.println(responseMessage);
			 
	    	System.out.println("***before decode");
	    	
			 byte[] base64DecodedResponse = Base64.decode(responseMessage.trim());
			 System.out.println("base64DecodedResponse--" + base64DecodedResponse.length);
			 String decodedString = new String(base64DecodedResponse);
			 System.out.println("Decoded String" + decodedString);
			 SAXParserFactory saxParserFactory = SAXParserFactory.newInstance();

			 // If we want to validate the doc we need to load the DTD
			 // saxParserFactory.setValidating(true);

			 // Get a SAXParser instance
			 SAXParser saxParser;
			 XMLhandler xmLhandler = new XMLhandler();
			try {
				saxParser = saxParserFactory.newSAXParser();
				 // Parse it
				 
				 saxParser.parse(new ByteArrayInputStream(decodedString.getBytes()), xmLhandler);
			} catch (Exception e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} 
			//byte[] base64DecodedResponse = org.opensaml.xml.util.Base64.decode(responseMessage);
			System.out.println("***after decode");
	      //after this line it is going to **matchesAuthRequest return values :true TODO trace it
	      relayState = SampleSAML2Utilities.getRelayState(httpRequest);
	      System.out.println("Relay state : " + relayState);
	      responseData.userName = "sushil";
	      System.out.println("Validating user ::: " + responseData.userName);
	      if (SampleSAML2Utilities.isRelayStateValid(relayState))
	      {
	    	logger.debug("Validating user : " + responseData.userName);
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
	    	eValidate.printStackTrace();
	      try
	      {
	        AuthenticationUtilities.getSecurityMonitorThing().fireFailedLoginEvent(responseData.userName, eValidate.getMessage());
	      }
	      catch (Exception e)
	      {
	        logger.error("Unable to fire failed login event: " + e.getMessage());
	        System.out.println("Unable to fire failed login event:");
	        e.printStackTrace();
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

	    //Fail safe code. Ass saving stuff 
	    try
	    {
	      String appKey = httpRequest.getParameter("appKey");
	      if ((appKey != null) && (!appKey.isEmpty())) {
	        matches = false;
	        return false;
	      }
	    }
	    catch (Throwable t){throw new AuthenticatorException(t);}
	    //end 
	    
	    String acsURL = null;
		acsURL = "/Thingworx/Home";
		logger.debug("Using ACS Url as" + acsURL);
		
	    String uri = httpRequest.getRequestURI();
	    if (uri != null && uri.length() > 0) {
	      if (uri.equalsIgnoreCase(acsURL))
	      {
	        String sMethod = httpRequest.getMethod();
	        RESTAPIConstants.Method method = RESTAPIConstants.getMethod(sMethod);
	        if ((method != null) && (method == RESTAPIConstants.Method.POST))
	        {
	          String contentType = httpRequest.getContentType();
	          if (contentType.equalsIgnoreCase("application/x-www-form-urlencoded"))
	          {
	        	 logger.debug("Inside if cond, content type : application form urlencoded" );
	            String samlResponse = SampleSAML2Utilities.getEncodedSAMLResponse(httpRequest);
	            if (samlResponse != null) {
	              matches = true;
	            }
	          }
	        }
	      }
	    }
	    
	    
	    logger.debug(" matchesAuthRequest saml response return val : " + matches);
	    System.out.println(" matchesAuthRequest saml response return val ::: " + matches);
	    
	//    String authnReqStr = httpRequest.getParameter("SAMLResponse").toString();
	   
	    
	    return matches;
	}

}
