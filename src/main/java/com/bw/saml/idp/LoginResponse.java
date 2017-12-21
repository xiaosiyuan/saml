package com.bw.saml.idp;

/**
 * @author Xiaosy
 * @date 2017-12-18 17:36
 */
public class LoginResponse {
    private Integer code;

    private String message;

    public Integer getCode() {
        return code;
    }

    public void setCode(Integer code) {
        this.code = code;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
