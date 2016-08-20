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

import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;
import bc.tls.BcSecurityPrototype;
import bc.tls.CipherSuite;
import bc.tls.logging.LogConsumer;
import bc.tls.logging.LogConsumerFactory;

public class BcTlsServer extends DefaultTlsServer {

	private static final LogConsumer LOG = LogConsumerFactory.getTaggedConsumer("Server");

	private final int[] defaultCs;
	private final BcSecurityPrototype securityPrototype;
	private final String hostname;

	private TlsSignerCredentials signerCredentials;

	public BcTlsServer(BcSecurityPrototype prototype, String host) {
		this.hostname = host;
		this.securityPrototype = prototype;
		this.defaultCs = CipherSuite.convert(this.securityPrototype.getCipherSuites());
	}

	@Override
	public int[] getCipherSuites() {
		return this.defaultCs;
	}

	@Override
	public ProtocolVersion getMinimumVersion() {
		return ProtocolVersion.TLSv12;
	}

	@Override
	public CertificateRequest getCertificateRequest() throws IOException {
		return this.securityPrototype.makeCertificateRequest();
	}

	@Override
	public int getSelectedCipherSuite() throws IOException {
		if (this.selectedCipherSuite == 0) {
			super.getSelectedCipherSuite();
		}

		this.securityPrototype.initialise(this.selectedCipherSuite);
		this.signerCredentials = this.securityPrototype.makeSignerCredentials();
		if (this.signerCredentials == null) {
			LOG.warn("There are no credentials available for this cipher suite");
		}

		return this.selectedCipherSuite;
	}

	@Override
	public TlsCredentials getCredentials() throws IOException {
		return signerCredentials;

	}
}
