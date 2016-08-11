/**
 * BouncyCastle TLS implementation
 * Copyright (C) 2016  super-horst
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation; either version 3 of the 
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 */
package bc.tls.socket;

import java.io.IOException;

import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.crypto.tls.TlsEncryptionCredentials;
import org.bouncycastle.crypto.tls.TlsFatalAlert;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;

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

	@Override
	public ProtocolVersion getMinimumVersion() {
		return ProtocolVersion.TLSv12;
	}

	@Override
	public CertificateRequest getCertificateRequest() throws IOException {
		return null;

	}

	@Override
	public int getSelectedCipherSuite() throws IOException {
		if (this.selectedCipherSuite == 0) {
			return super.getSelectedCipherSuite();
		}
		return this.selectedCipherSuite;
	}

	@Override
	protected TlsSignerCredentials getDSASignerCredentials() throws IOException {
		throw new TlsFatalAlert(AlertDescription.internal_error);
	}

	@Override
	protected TlsSignerCredentials getECDSASignerCredentials() throws IOException {
		throw new TlsFatalAlert(AlertDescription.internal_error);
	}

	@Override
	protected TlsEncryptionCredentials getRSAEncryptionCredentials() throws IOException {
		throw new TlsFatalAlert(AlertDescription.internal_error);
	}

	@Override
	protected TlsSignerCredentials getRSASignerCredentials() throws IOException {
		throw new TlsFatalAlert(AlertDescription.internal_error);
	}

}
