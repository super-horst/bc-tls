package bc.tls.socket;

import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.TlsCredentials;

import bc.tls.CipherSuite;

public class BcTlsServer extends DefaultTlsServer {
	
	/**
	 * Authentication instance to retrieve server certificate.
	 */
	private final int[] defaultCs;
	private final TlsCredentials credentials;
	private final String hostname;
	
	public BcTlsServer(TlsCredentials credentials, String[] defaultCipherSuites, String host) {
		this.credentials = credentials;
		this.defaultCs = CipherSuite.convert(defaultCipherSuites);
		this.hostname = host;
	}
	
	@Override
	public int[] getCipherSuites() {
		return defaultCs;
	}
	
	public int getSelectedCipherSuite() {
		return this.selectedCipherSuite;
	}

	@Override
	public ProtocolVersion getMinimumVersion() {
		return ProtocolVersion.TLSv12;
	}

}
