package bc.tls.socket;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Hashtable;

import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.ExtensionType;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.TlsAuthentication;

import bc.tls.CipherSuite;

public class BcTlsClient extends DefaultTlsClient {

	/**
	 * Authentication instance to retrieve server certificate.
	 */
	private final int[] defaultCs;
	private final TlsAuthentication authentication;
	private final String hostname;

	public BcTlsClient(TlsAuthentication authentication, String[] defaultCipherSuites, String hostname) {
		this.defaultCs = CipherSuite.convert(defaultCipherSuites);
		this.hostname = hostname;
		this.authentication = authentication;
	}
	
	@Override
	public int[] getCipherSuites() {
		return defaultCs;
	}
	
	public int getSelectedCipherSuite() {
		return this.selectedCipherSuite;
	}

	@Override
	public TlsAuthentication getAuthentication() throws IOException {
		return authentication;
	}

	@Override
	public ProtocolVersion getMinimumVersion() {
		return ProtocolVersion.TLSv12;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.bouncycastle.crypto.tls.AbstractTlsClient#getClientExtensions()
	 */
	@Override
	@Deprecated
	public Hashtable<Integer, byte[]> getClientExtensions() throws IOException {
		@SuppressWarnings("unchecked")
		Hashtable<Integer, byte[]> clientExtensions = super.getClientExtensions();
		if (clientExtensions == null) {
			clientExtensions = new Hashtable<Integer, byte[]>();
		}

		final ByteArrayOutputStream extBaos = new ByteArrayOutputStream();
		final DataOutputStream extOS = new DataOutputStream(extBaos);

		if (this.hostname != null) {
			final byte[] hostnameBytes = this.hostname.getBytes();
			final int snl = hostnameBytes.length;

			// OpenSSL breaks if an extension with length "0" sent, they expect
			// at least
			// an entry with length "0"
			extOS.writeShort(snl == 0 ? 0 : snl + 3); // entry size
			if (snl > 0) {
				extOS.writeByte(0); // name type = hostname
				extOS.writeShort(snl); // name size
				if (snl > 0) {
					extOS.write(hostnameBytes);
				}
			}

			extOS.close();
			clientExtensions.put(ExtensionType.server_name, extBaos.toByteArray());
		}

		return clientExtensions;
	}
}
