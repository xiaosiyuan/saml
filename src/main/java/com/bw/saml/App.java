package com.bw.saml;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Hello world!
 *
 */
@SpringBootApplication
public class App 
{
    public static void main( String[] args )
    {
        //System.setProperty("javax.xml.parsers.DocumentBuilderFactory","org.apache.xerces.jaxp.DocumentBuilderFactoryImpl");
        System.out.println( "Hello World!" );
        SpringApplication.run(App.class,args);
    }
}
