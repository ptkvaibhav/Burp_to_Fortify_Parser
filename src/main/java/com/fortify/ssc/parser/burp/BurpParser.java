package com.fortify.ssc.parser.burp;

import com.fortify.plugin.spi.parser.IScanParser;
import com.fortify.plugin.spi.parser.PluginParserBase;
import com.fortify.plugin.spi.parser.ParseContext;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.util.UUID;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.util.zip.ZipOutputStream;
import java.util.zip.ZipEntry;

/**
 * BurpParser is a sample SSC parser that converts a Burp Suite XML report into an FPR file.
 */
public class BurpParser extends PluginParserBase implements IScanParser {

    @Override
    public void start() {
        System.out.println("Starting Burp Parser Plugin...");
    }

    @Override
    public void parse(InputStream scanInput, OutputStream fprOutput, ParseContext context) throws IOException {
        try {
            XMLInputFactory factory = XMLInputFactory.newInstance();
            XMLStreamReader reader = factory.createXMLStreamReader(scanInput);

            // Create a ZipOutputStream to generate an FPR (which is a ZIP archive containing audit.fvdl)
            ZipOutputStream zos = new ZipOutputStream(fprOutput);
            zos.putNextEntry(new ZipEntry("audit.fvdl"));

            StringBuilder sb = new StringBuilder();
            sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
            sb.append("<FVDL>");
            sb.append("<Vulnerabilities>");

            // Process the Burp XML and generate vulnerability entries.
            while (reader.hasNext()) {
                int event = reader.next();
                if (event == XMLEvent.START_ELEMENT && "issue".equals(reader.getLocalName())) {
                    String uuid = UUID.randomUUID().toString();
                    String issueContent = reader.getElementText();
                    sb.append("<Vulnerability>");
                    sb.append("<ClassID>").append(uuid).append("</ClassID>");
                    sb.append("<AnalyzerName>Burp Suite</AnalyzerName>");
                    sb.append("<Kingdom>Input Validation</Kingdom>");
                    sb.append("<Type>").append(issueContent).append("</Type>");
                    sb.append("<Abstract>Automatically generated vulnerability.</Abstract>");
                    sb.append("</Vulnerability>");
                }
            }
            sb.append("</Vulnerabilities>");
            sb.append("</FVDL>");

            zos.write(sb.toString().getBytes("UTF-8"));
            zos.closeEntry();
            zos.close();

            System.out.println("FPR file successfully created.");
        } catch (XMLStreamException e) {
            throw new IOException("Error parsing Burp XML report", e);
        }
    }

    @Override
    public void end() {
        System.out.println("Burp Parser Plugin completed.");
    }
}