package bc.tls.util;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.X509CertParser;
import org.bouncycastle.x509.util.StreamParsingException;

public class Utility {
	
	public static X509Certificate loadX509Certificate(File cert) throws IOException {
		return loadX509Certificate(new FileInputStream(cert));
	}
	
	public static X509Certificate loadX509Certificate(byte[] cert) throws IOException {
		return loadX509Certificate(new ByteArrayInputStream(cert));
	}
	
	public static X509Certificate loadX509Certificate(InputStream in) throws IOException {
		X509CertParser parser = new X509CertParser();
		parser.engineInit(in);
		try {
			return (X509Certificate)parser.engineRead();
		} catch (StreamParsingException e) {
			throw new IOException(e);
		} finally {
			in.close();
		}
		
	}
	

}
