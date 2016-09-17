package com.flex.twx.security.samlsso;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

public class XMLhandler extends DefaultHandler {

    private String samlVO;

    public XMLhandler() {
        samlVO = "";
    }

    @Override
    public void startElement(String uri, String localName, String qName,
        Attributes attributes) throws SAXException {

        // Managing a LogoutRequest means that we are going to build a LogoutResponse
        if(qName.equals("saml2:NameID")){
        	System.out.println("saml2:NameID . format");
        	System.out.println(attributes.getValue("Format"));
        	System.out.println("saml2:NameID . qname");
        	System.out.println(attributes.getValue(qName));
        }
    	if (qName.equals("saml2p:Response")) {
            // The ID value of a request will be the LogoutResponse's InReponseTo attribute 
            System.out.println( "IN start element " +attributes.getValue("ID"));
            
            // From the destination we can get the Issuer element
           /* String destination = attributes.getValue("Destination");
            if (destination != null) {
                URL destinationUrl = null;
                try {
                    destinationUrl = new URL(destination);
                } catch (MalformedURLException e) {
                     // TODO: We could set the server hostname (take it from a property), but this URL SHOULD be well formed!
                     e.printStackTrace();
                }
                samlVO.setIssuer(destinationUrl.getHost());
            }*/
        }   
    }

   

}