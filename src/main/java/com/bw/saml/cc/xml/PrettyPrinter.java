package com.bw.saml.cc.xml;

import org.w3c.dom.Document;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;


/**
This class "pretty prints" an XML stream to something more human-readable.
It duplicates the character content with some modifications to whitespace, 
restoring line breaks and a simple pattern of indenting child elements.

This version of the class acts as a SAX 2.0 <code>DefaultHandler</code>,
so to provide the unformatted XML just pass a new instance to a SAX parser.
Its output is via the {@link #toString toString} method.

One major limitation:  we gather character data for elements in a single
buffer, so mixed-content documents will lose a lot of data!  This works
best with data-centric documents where elements either have single values
or child elements, but not both.

@author Will Provost
*/
/*
Copyright 2002-2003 by Will Provost.
All rights reserved.
*/
public class PrettyPrinter
    extends DefaultHandler
{
    /**
    Convenience method to wrap pretty-printing SAX pass over existing content.
    */
    public static String prettyPrint (byte[] content)
    {
        try
        {
            PrettyPrinter pretty = new PrettyPrinter ();
            SAXParserFactory factory = SAXParserFactory.newInstance ();
            factory.setFeature
                ("http://xml.org/sax/features/namespace-prefixes", true);
            factory.newSAXParser ().parse 
                (new ByteArrayInputStream (content), pretty);
            return pretty.toString ();
        }
        catch (Exception ex)
        {
            ex.printStackTrace ();
            return "EXCEPTION: " + ex.getClass ().getName () + " saying \"" +
                ex.getMessage () + "\"";
        }
    }
    
    /**
    Convenience method to wrap pretty-printing SAX pass over existing content.
    */
    public static String prettyPrint (String content)
    {
        try
        {
            PrettyPrinter pretty = new PrettyPrinter ();
            SAXParserFactory factory = SAXParserFactory.newInstance ();
            factory.setFeature
                ("http://xml.org/sax/features/namespace-prefixes", true);
            factory.newSAXParser ().parse (content, pretty);
            return pretty.toString ();
        }
        catch (Exception ex)
        {
            ex.printStackTrace ();
            return "EXCEPTION: " + ex.getClass ().getName () + " saying \"" +
                ex.getMessage () + "\"";
        }
    }
    
    /**
    Convenience method to wrap pretty-printing SAX pass over existing content.
    */
    public static String prettyPrint (InputStream content)
    {
        try
        {
            PrettyPrinter pretty = new PrettyPrinter ();
            SAXParserFactory factory = SAXParserFactory.newInstance ();
            factory.setFeature
                ("http://xml.org/sax/features/namespace-prefixes", true);
            factory.newSAXParser ().parse (content, pretty);
            return pretty.toString ();
        }
        catch (Exception ex)
        {
            ex.printStackTrace ();
            return "EXCEPTION: " + ex.getClass ().getName () + " saying \"" +
                ex.getMessage () + "\"";
        }
    }

    /**
    Convenience method to wrap pretty-printing SAX pass over existing content.
    */
    public static String prettyPrint (Document doc)
        throws TransformerException
    {
        try
        {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream ();
            TransformerFactory.newInstance ().newTransformer()
                .transform (new DOMSource (doc), new StreamResult (buffer));
            byte[] rawResult = buffer.toByteArray ();
            buffer.close ();
            
            return prettyPrint (rawResult);
        }
        catch (Exception ex)
        {
            ex.printStackTrace ();
            return "EXCEPTION: " + ex.getClass ().getName () + " saying \"" +
                ex.getMessage () + "\"";
        }
    }
    
    public static class StreamAdapter
        extends OutputStream
    {
        public StreamAdapter (Writer finalDestination)
        {
            this.finalDestination = finalDestination;
        }
        
        public void write (int b)
        {
            out.write (b);
        }
        
        public void flushPretty ()
            throws IOException
        {
            PrintWriter finalPrinter = new PrintWriter (finalDestination);
            finalPrinter.println 
                (PrettyPrinter.prettyPrint (out.toByteArray ()));
            finalPrinter.close ();
            out.close ();
        }
        
        private ByteArrayOutputStream out = new ByteArrayOutputStream ();
        Writer finalDestination;
    }
    
    /**
    Call this to get the formatted XML post-parsing.
    */
    public String toString ()
    {
        return output.toString ();
    }
    
    /**
    Prints the XML declaration.
    */
    public void startDocument () 
        throws SAXException 
    {
        output.append ("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>")
              .append (endLine);
    }
    
    /**
    Prints a blank line at the end of the reformatted document.
    */
    public void endDocument () throws SAXException 
    {
        output.append (endLine);
    }

    /**
    Writes the start tag for the element.
    Attributes are written out, one to a text line.  Starts gathering
    character data for the element.
    */
    public void startElement 
            (String URI, String name, String qName, Attributes attributes) 
        throws SAXException 
    {
        if (justHitStartTag)
            output.append ('>');

        output.append (endLine)
              .append (indent)
              .append ('<')
              .append (qName);

        int length = attributes.getLength ();        
        for (int a = 0; a < length; ++a)
            output.append (endLine)
                  .append (indent)
                  .append (standardIndent)
                  .append (attributes.getQName (a))
                  .append ("=\"")
                  .append (attributes.getValue (a))
                  .append ('\"');
                  
        if (length > 0)
            output.append (endLine)
                  .append (indent);
            
        indent += standardIndent;
        currentValue = new StringBuffer ();
        justHitStartTag = true;
    }
    
    /**
    Checks the {@link #currentValue} buffer to gather element content.
    Writes this out if it is available.  Writes the element end tag.
    */
    public void endElement (String URI, String name, String qName) 
        throws SAXException 
    {
        indent = indent.substring 
            (0, indent.length () - standardIndent.length ());
        
        if (currentValue == null)
            output.append (endLine)
                  .append (indent)
                  .append ("</")
                  .append (qName)
                  .append ('>');
        else if (currentValue.length () != 0)
            output.append ('>')
                  .append (currentValue.toString ())
                  .append ("</")
                  .append (qName)
                  .append ('>');
        else
            output.append ("/>");
              
        currentValue = null;
        justHitStartTag = false;
    }
        
    /**
    When the {@link #currentValue} buffer is enabled, appends character
    data into it, to be gathered when the element end tag is encountered.
    */
    public void characters (char[] chars, int start, int length) 
        throws SAXException 
    {
        if (currentValue != null)
            currentValue.append (escape (chars, start, length));
    }

    /**
    Filter to pass strings to output, escaping <b>&lt;</b> and <b>&amp;</b>
    characters to &amp;lt; and &amp;amp; respectively.
    */
    private static String escape (char[] chars, int start, int length)
    {
        StringBuffer result = new StringBuffer ();
        for (int c = start; c < start + length; ++c)
            if (chars[c] == '<')
                result.append ("&lt;");
            else if (chars[c] == '&')
                result.append ("&amp;");
            else
                result.append (chars[c]);
                
        return result.toString ();
    }
    
    /**
    This whitespace string is expanded and collapsed to manage the output
    indenting.
    */
    private String indent = "";

    /**
    A buffer for character data.  It is &quot;enabled&quot; in 
    {@link #startElement startElement} by being initialized to a 
    new <b>StringBuffer</b>, and then read and reset to 
    <code>null</code> in {@link #endElement endElement}.
    */
    private StringBuffer currentValue = null;

    /**
    The primary buffer for accumulating the formatted XML.
    */
    private StringBuffer output = new StringBuffer ();    
    
    private boolean justHitStartTag;
    
    private static final String standardIndent = "  ";
    private static final String endLine = 
        System.getProperty ("line.separator");
}

