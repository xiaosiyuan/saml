package com.bw.saml.idp;

import com.bw.saml.cc.pojo.AuthnRequestField;
import com.bw.saml.cc.service.AuthnRequestHandler;
import com.bw.saml.cc.service.SamlResponseGenerator;
import com.bw.saml.constants.Constants;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

/**
 * @author Xiaosy
 * @date 2017-11-14 14:59
 */
@RestController
@RequestMapping("/idp")
public class IdpController {

    @Autowired
    private AuthnRequestHandler authnRequestHandler;
    @Autowired
    private SamlResponseGenerator samlResponseGenerator;
    @Autowired
    private SamlRequestCache samlRequestCache;
    @GetMapping("/sso")
    public void sso(String SAMLRequest, HttpServletRequest request,HttpServletResponse response) throws Exception {
        System.out.println("samlRequest = " + SAMLRequest);
        /**
         * 是否在idp端已登录
         */
        Cookie[]cookies = request.getCookies();
        String cookie_value = null;
        if(cookies != null){
            for(Cookie cookie:cookies){
                if(Constants.IDP_COOKIE_KEY.equalsIgnoreCase(cookie.getName())){
                    cookie_value = cookie.getValue();
                }
            }
        }
        if(cookie_value != null && Constants.IDP_COOKIE_VALUE.equalsIgnoreCase(cookie_value)){
            //已登录，解析SAMLRequest对象,查找出用户信息
            String email = "test@qq.com";
            AuthnRequestField authnRequestField = authnRequestHandler.handleAuthnRequest(SAMLRequest);
            String result = samlResponseGenerator.generateSamlResponse(email,authnRequestField);
            response.reset();
            PrintWriter printWriter = response.getWriter();
            printWriter.write( samlResponseGenerator.getForm(authnRequestField.getAssertionConsumerServiceUrl(), new Base64().encodeAsString(result.getBytes("utf-8"))));
            printWriter.flush();
            printWriter.close();
            return;
        }else {
            //重定向到登陆页面
            samlRequestCache.setSAMLRequest(SAMLRequest);
            response.sendRedirect("/login.html?SAMLRequest=" + SAMLRequest);
            return;
        }

    }

    @PostMapping("/auth")
    public LoginResponse login(String username, String password, HttpServletRequest req, HttpServletResponse res) throws Exception {
        LoginResponse loginResponse = new LoginResponse();
        if ("admin".equals(username) && "admin".equals(password)) {
            String email = "test@qq.com";
            //鉴权通过
            System.out.println("auth pass...");
            AuthnRequestField authnRequestField = authnRequestHandler.handleAuthnRequest(samlRequestCache.getSAMLRequest());
            System.out.println(authnRequestField);
            String result = samlResponseGenerator.generateSamlResponse(email, authnRequestField);
            res.reset();
            Cookie cookie = new Cookie(Constants.IDP_COOKIE_KEY,Constants.IDP_COOKIE_VALUE);
            cookie.setPath("/");
            res.addCookie(cookie);
            PrintWriter printWriter = res.getWriter();
            printWriter.write(samlResponseGenerator.getForm(authnRequestField.getAssertionConsumerServiceUrl(), new Base64().encodeAsString(result.getBytes("utf-8"))));
            printWriter.flush();
            printWriter.close();
            return null;
        }
        loginResponse.setCode(1);
        return loginResponse;
    }
}
