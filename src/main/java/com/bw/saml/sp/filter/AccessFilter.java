package com.bw.saml.sp.filter;

import com.bw.saml.cc.saml.SAMLRequest;
import com.bw.saml.constants.Constants;
import org.apache.commons.codec.binary.Base64;

import javax.servlet.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.zip.Deflater;

/**
 * @author Xiaosy
 * @date 2017-12-14 15:44
 */
public class AccessFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest)request;
        HttpServletResponse httpServletResponse = (HttpServletResponse)response;

        /**
         * sp端：如果有cookie且没过期，直接允许访问，否则，生成SAMLRequest后重定向到idp sso地址
         */
        Cookie[]cookies = httpServletRequest.getCookies();
        String cookie_value = null;
        if(cookies != null){
            for(Cookie cookie:cookies){
                if(Constants.SP_COOKIE_KEY.equalsIgnoreCase(cookie.getName())){
                    cookie_value = cookie.getValue();
                }
            }
        }

        if(cookie_value != null && Constants.SP_COOKIE_VALUE.equalsIgnoreCase(cookie_value)){
            System.out.println("access");
            chain.doFilter(request,response);
        }else {
            SAMLRequest samlRequest = new SAMLRequest();
            try {
                String samlRequestXmlString = samlRequest.createRequestXmlString(Constants.IDP_SSO_URL,Constants.SP_ACS_URL,Constants.SP_ENTITY_ID);
                System.out.println(samlRequestXmlString);
                String str = URLEncoder.encode(new Base64().encodeAsString(compress(samlRequestXmlString.getBytes("utf-8"))),"utf-8");
                System.out.println(str);
                httpServletResponse.sendRedirect(Constants.IDP_SSO_URL + "?SAMLRequest=" + str);
                return;
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    public void destroy() {

    }

    private byte[] compress(byte[] inputByte) throws IOException {
        int len = 0;
        Deflater defl = new Deflater(Deflater.DEFAULT_COMPRESSION,true);
        defl.setInput(inputByte);
        defl.finish();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] outputByte = new byte[1024];
        try {
            while (!defl.finished()) {
                // 压缩并将压缩后的内容输出到字节输出流bos中
                len = defl.deflate(outputByte);
                bos.write(outputByte, 0, len);
            }
            defl.end();
        } finally {
            bos.close();
        }
        return bos.toByteArray();
    }
}
