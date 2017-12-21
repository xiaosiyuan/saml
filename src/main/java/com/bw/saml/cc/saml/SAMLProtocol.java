package com.bw.saml.cc.saml;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.*;
import org.opensaml.xml.io.MarshallingException;

import javax.xml.transform.TransformerException;
import java.io.IOException;

/**
Simple examples of coding to the OpenSAML API.
Methods here can write SAMLP queries and responses for each of the three
main types: authentication, authorization decision, and attributes.

@author Will Provost
*/
/*
Copyright 2006-2009 Will Provost.
All rights reserved by Capstone Courseware, LLC.
*/
public class SAMLProtocol
    extends SAMLAssertion
{
    private static final String QUERY_SUFFIX = "Query.xml";
    private static final String RESPONSE_SUFFIX = "Response.xml";

    private static void die ()
    {
        System.out.println ("Usage: java cc.saml.SAMLProtocol ");
        System.out.println 
            ("  <query|response> <authn|attr|authz> <simple-name>");
        System.exit (-1);
    }
    
    /**
    Parses the command line for instructions to write a SAML query or
    response in one of the three main types, and for a base filename.
    The command methods will automatically append either "Query.xml" or
    "Response.xml" to the base name.
    */
        
    /**
    Helper method to generate and pretty-print a response, based on a given
    query (for our inResponseTo value) and an assertion.
    */
    public void printResponse (Assertion assertion, String filename)
        throws IOException, MarshallingException, TransformerException
    {
        Response response = createResponse (assertion);

        Issuer issuer = create (Issuer.class, Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue ("http://somecom.com/SomeJavaAssertingParty");
        response.setIssuer (issuer);

        if (filename != null)
            try
            {
                RequestAbstractType query = (RequestAbstractType) 
                    readFromFile (filename + QUERY_SUFFIX);
                response.setInResponseTo (query.getID ());
            }
            catch (Exception ex)
            {
                System.out.println ("Couldn't read corresponding query file; " +
                    "InResponseTo will be missing.");
            }

        printToFile (response, 
            filename != null ? filename + RESPONSE_SUFFIX : null);
    }

    /**
    Creates a file whose contents are a SAML authentication query.
    */
    public AuthnQuery createStockAuthnQuery ()
        throws Exception
    {
        DateTime now = new DateTime ();
        Issuer issuer = create (Issuer.class, Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue ("http://somecom.com/SomeJavaRelyingParty");
        
        NameID nameID = create (NameID.class, NameID.DEFAULT_ELEMENT_NAME);
        nameID.setValue ("harold_dt");
        
        Subject subject = create (Subject.class, Subject.DEFAULT_ELEMENT_NAME);
        subject.setNameID (nameID);
        
        AuthnContextClassRef ref = create (AuthnContextClassRef.class, 
            AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        ref.setAuthnContextClassRef (AuthnContext.PPT_AUTHN_CTX);
        
        RequestedAuthnContext authnContext = create 
            (RequestedAuthnContext.class, 
                RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
        authnContext.getAuthnContextClassRefs ().add (ref);

        AuthnQuery query = create 
            (AuthnQuery.class, AuthnQuery.DEFAULT_ELEMENT_NAME);
        query.setID ("AuthnQuery12345789");
        query.setIssueInstant (now);
        query.setIssuer (issuer);
        query.setSubject (subject);
        query.setRequestedAuthnContext (authnContext);
        
        return query;
    }
    
    /**
    Creates a file whose contents are a SAML attribute query.
    */
    public AttributeQuery createStockAttributeQuery ()
        throws Exception
    {
        DateTime now = new DateTime ();
        Issuer issuer = create (Issuer.class, Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue ("http://somecom.com/SomeJavaRelyingParty");
        
        NameID nameID = create (NameID.class, NameID.DEFAULT_ELEMENT_NAME);
        nameID.setValue ("harold_dt");
        
        Subject subject = create (Subject.class, Subject.DEFAULT_ELEMENT_NAME);
        subject.setNameID (nameID);
        
        Attribute attribute1 = create 
            (Attribute.class, Attribute.DEFAULT_ELEMENT_NAME);
        attribute1.setName ("FullName");
        
        Attribute attribute2 = create 
            (Attribute.class, Attribute.DEFAULT_ELEMENT_NAME);
        attribute2.setName ("JobTitle");

        AttributeQuery query = create 
            (AttributeQuery.class, AttributeQuery.DEFAULT_ELEMENT_NAME);
        query.setID ("AttrQuery12345789");
        query.setIssueInstant (now);
        query.setIssuer (issuer);
        query.setSubject (subject);
        query.getAttributes ().add (attribute1);
        query.getAttributes ().add (attribute2);
        
        return query;
    }
    
    /**
    Creates a file whose contents are a SAML authorization-decision query.
    */
    public AuthzDecisionQuery createStockAuthzDecisionQuery ()
        throws Exception
    {
        DateTime now = new DateTime ();
        Issuer issuer = create (Issuer.class, Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue ("http://somecom.com/SomeJavaRelyingParty");
        
        NameID nameID = create (NameID.class, NameID.DEFAULT_ELEMENT_NAME);
        nameID.setValue ("harold_dt");
        
        Subject subject = create (Subject.class, Subject.DEFAULT_ELEMENT_NAME);
        subject.setNameID (nameID);
        
        Action action = create (Action.class, Action.DEFAULT_ELEMENT_NAME);
        action.setAction ("read");
        action.setNamespace (Action.RWEDC_NS_URI);

        AuthzDecisionQuery query = create (AuthzDecisionQuery.class, 
            AuthzDecisionQuery.DEFAULT_ELEMENT_NAME);
        query.setID ("AuthzQuery12345789");
        query.setIssueInstant (now);
        query.setIssuer (issuer);
        query.setSubject (subject);
        query.setResource ("http://mycom.com/Repository/Private");
        query.getActions ().add (action);
        
        return query;
    }
}
