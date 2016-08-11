package bc.tls;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertParser;
import org.bouncycastle.x509.util.StreamParsingException;

public class TestTools {
	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

	public static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}

	public static X509Certificate loadCert(File certFile) throws IOException {
		try (FileInputStream fis = new FileInputStream(certFile)) {
			return loadCert(fis);
		} catch (StreamParsingException e) {
			throw new IOException(e);
		}
	}

	public static X509Certificate loadCert(InputStream stream) throws StreamParsingException {
		X509CertParser certParser = new X509CertParser();

		certParser.engineInit(stream);
		return (X509Certificate) certParser.engineRead();
	}

	public static String getCommonName(X509Certificate cert) {
		return getDnField(cert, BCStyle.CN);
	}

	static final String getDnField(X509Certificate cert, ASN1ObjectIdentifier oid) {
		X500Name x500name;
		try {
			x500name = new JcaX509CertificateHolder(cert).getSubject();
		} catch (CertificateEncodingException e) {
			throw new IllegalArgumentException(e);
		}
		RDN cn = x500name.getRDNs(oid)[0];

		return IETFUtils.valueToString(cn.getFirst().getValue());

	}

	public static <T> T getFirst(Collection<T> collect) {
		for (T t : collect) {
			return t;
		}
		return null;
	}

	public static synchronized void registerBcProvider() {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}
}
