package com.bw.saml.cc.service;

import com.bw.saml.cc.pojo.AuthnRequestField;
import com.bw.saml.cc.saml.SAML;
import com.bw.saml.cc.saml.SAMLAssertion;
import com.bw.saml.cc.saml.SAMLSignature;
import com.bw.saml.constants.Constants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.util.UUID;

/**
 * 生成SAMLResponse字符串
 *
 * @author Xiaosy
 * @date 2017-12-14 14:31
 */
@Service
public class SamlResponseGenerator {

    private String email;
    private String spEntityId;
    private String acsUrl;
    private String inResponseTo;

    public void init(String email,AuthnRequestField requestField){
        this.email = email;
        if(requestField == null){
            this.spEntityId = Constants.SP_ENTITY_ID;
            this.acsUrl = Constants.SP_ACS_URL;
        }else {
            this.spEntityId = requestField.getSpIssuer();
            this.acsUrl = requestField.getAssertionConsumerServiceUrl();
            this.inResponseTo = requestField.getRequestId();
        }
    }

    /**
     * 生成response字符串
     * @param email
     * @param requestField
     * @return
     * @throws Exception
     */
    public String generateSamlResponse(String email, AuthnRequestField requestField) throws Exception {
        init(email,requestField);
        SAML saml = new SAML(Constants.IDP_ENTITY_ID);
        //创建Subject
        Subject subject = saml.createSubject(email, NameID.EMAIL,"bearer",this.acsUrl);
        //创建断言Assertion
        String assertionId = UUID.randomUUID().toString();
        SAMLAssertion samlAssertion = new SAMLAssertion();
        Assertion assertion = samlAssertion.createStockAuthnAssertion(Constants.IDP_ENTITY_ID,assertionId,spEntityId);
        assertion.setSubject(subject);
        //创建response
        Response response = saml.createResponse(assertion,inResponseTo);
        //签名
        SAMLSignature samlSignature = new SAMLSignature();
        Document document = saml.asDOMDocument(response);
        samlSignature.signSAMLObject(document,assertionId, document.getElementsByTagName("saml:Assertion").item(0));
        DOMSource source=new DOMSource(document);
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer former=tf.newTransformer();
        former.setOutputProperty(OutputKeys.STANDALONE, "yes");
        StringWriter sw = new StringWriter();
        StreamResult sr = new StreamResult(sw);
        former.transform(source, sr);
        String result=sw.toString();
        return result;
    }


    public String getForm(String url,String response){
        return "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">\n" +
                "<head>\n" +
                "<meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\" />\n" +
                "<title>POST data</title>\n" +
                "</head>\n" +
                "<body onload=\"document.forms[0].submit()\">\n" +
                "<noscript>\n" +
                "<p><strong>Note:</strong> Since your browser does not support JavaScript, you must press the button below once to proceed.</p>\n" +
                "</noscript>\n" +
                "\t<form method=\"post\" action=\"" + url + "\">\n" +
                "\t\t<input type=\"hidden\" name=\"SAMLResponse\" value=\"" + response + "\"/><br/>\n" +
                "\t\t<noscript><input type=\"submit\" value=\"Submit\" /></noscript>\n" +
                "\t</form>\n" +
                "</body>\n" +
                "</html>";
    }
    public static void main(String[] args) {
        System.out.println(UUID.randomUUID().toString());
    }
}
