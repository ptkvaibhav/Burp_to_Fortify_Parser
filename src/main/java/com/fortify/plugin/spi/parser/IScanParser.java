package com.fortify.plugin.spi.parser;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;

public interface IScanParser {
    void start();
    void parse(InputStream scanInput, OutputStream fprOutput, ParseContext context) throws IOException;
    void end();
}