package com.flex.twx.security.samlsso;

import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;

import com.thingworx.common.RESTAPIConstants;
import com.thingworx.common.exceptions.InvalidRequestException;
import com.thingworx.logging.LogUtilities;
import com.thingworx.metadata.annotations.ThingworxConfigurationTableDefinitions;
import com.thingworx.security.authentication.AuthenticatorException;
import com.thingworx.security.authentication.CustomAuthenticator;

@ThingworxConfigurationTableDefinitions(tables={@com.thingworx.metadata.annotations.ThingworxConfigurationTableDefinition(name="AuthenticatorConfiguration", description="Authenticator Configuration", isMultiRow=false, dataShape=@com.thingworx.metadata.annotations.ThingworxDataShapeDefinition(fields={@com.thingworx.metadata.annotations.ThingworxFieldDefinition
		(name="ProviderName", description="Name of the Provider (TWX Platform)", baseType="STRING", aspects={"defaultValue:Thingworx"}), @com.thingworx.metadata.annotations.ThingworxFieldDefinition(name="ACSURL", description="Assertion Consumer Service URL", baseType="STRING", aspects={"defaultValue:http://localhost:8080/Thingworx/Home"}), @com.thingworx.metadata.annotations.ThingworxFieldDefinition
		(name="SingleSignOnURL", description="URL to Single Sign On Page", baseType="STRING", aspects={"defaultValue:https://ec2-52-66-14-73.ap-south-1.compute.amazonaws.com:9443/samlsso?spEntityID=Thingworx"})}))})
public class SAML2RequestHandlerAuthenticator extends CustomAuthenticator {

	public static final Logger logger = LogUtilities.getInstance().getApplicationLogger(SAML2RequestHandlerAuthenticator.class);

	private static final String INVALID_AUTHENTICATION_MESSAGE = "Authentication failed.  Please make sure the credentials are correct.";
	private static final String CONFIGURATION_TABLENAME = "AuthenticatorConfiguration";
	private static final String CONFIGURATION_KEYNAME_PROVIDERNAME = "ProviderName";
	private static final String CONFIGURATION_KEYNAME_SSOURL = "SingleSignOnURL";
	private static final String CONFIGURATION_KEYNAME_ACSURL = "ACSURL";

	public SAML2RequestHandlerAuthenticator(){
		setPriority(2);
		setSupportsSession(false);
	}

	public boolean matchesAuthRequest(HttpServletRequest httpRequest)
			throws AuthenticatorException{
		boolean matches = true;
		try{
			String appKey = httpRequest.getParameter("appKey");
			if ((appKey != null) && (!appKey.isEmpty())) {
				matches = false;
				logger.debug("**Request received with AppKey");
			}
		}catch (Throwable t){
			logger.error("Encountered error :" + t.getMessage() ) ;
			throw new AuthenticatorException(t);
		}
		return matches;
	}

	public void authenticate(HttpServletRequest httpRequests, HttpServletResponse httpResponse)
			throws AuthenticatorException
	{
		try{
			String providerName = getConfigurationTable(CONFIGURATION_TABLENAME).getRowValue(CONFIGURATION_KEYNAME_PROVIDERNAME).getValue().toString(); //"Thingworx";
			logger.debug("SAML ProviderName: " + providerName);

			String acsURL = getConfigurationTable(CONFIGURATION_TABLENAME).getRowValue(CONFIGURATION_KEYNAME_ACSURL).getValue().toString();//"http://localhost:8080/Thingworx/Home";
			logger.debug("SAML acsURL: " + acsURL);

			String ssoURL = getConfigurationTable(CONFIGURATION_TABLENAME).getRowValue(CONFIGURATION_KEYNAME_SSOURL).getValue().toString(); //"https://localhost:9443/samlsso?spEntityID=Thingworx"; 
			logger.debug("SAML ssoURL: " + ssoURL);

			String samlRequest = SampleSAML2Utilities.generateSAMLRequest(providerName, acsURL);
			String relayState = SampleSAML2Utilities.createNewRelayState();
			logger.debug("SAML RelayState: " + relayState);

			StringBuilder htmlForm = new StringBuilder();
			htmlForm.append("<html><body>");
			htmlForm.append("<form method=\"post\" action=\"" + ssoURL + "\">");
			htmlForm.append("<input type=\"hidden\" name=\"SAMLRequest\" value=\"" + samlRequest + "\"/>");
			htmlForm.append("<input type=\"hidden\" name=\"RelayState\" value=\"" + relayState + "\"/>");
			htmlForm.append("<input type=\"submit\" value=\"Submit\"/>");
			htmlForm.append("</form></body>");
			htmlForm.append("<script type=\"text/javascript\">");
			htmlForm.append("window.onload = function() { document.forms[0].submit(); }");
			htmlForm.append("</script></html>");

			PrintWriter writer = httpResponse.getWriter();
			writer.append(htmlForm.toString());
			writer.flush();
			writer.close();
		}catch (Throwable t){
			logger.error("An error occurred while attempting to send a SAML2 Authentication Request: " + t.getMessage());
			t.printStackTrace();
			throw new AuthenticatorException(new InvalidRequestException("Unable to login with IDP", RESTAPIConstants.StatusCode.STATUS_UNAUTHORIZED));
		}
	}

	public void issueAuthenticationChallenge(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
			throws AuthenticatorException
	{
		InvalidRequestException ire = new InvalidRequestException("Authentication failed.  Please make sure the credentials are correct.", RESTAPIConstants.StatusCode.STATUS_UNAUTHORIZED);
		throw new AuthenticatorException(ire);
	}
}