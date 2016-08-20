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
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.TlsAuthentication;

import bc.tls.BcSecurityPrototype;
import bc.tls.CipherSuite;
import bc.tls.logging.LogConsumer;
import bc.tls.logging.LogConsumerFactory;

/**
 * BC-tls client
 * 
 * @author super-horst
 *
 */
public class BcTlsClient extends DefaultTlsClient {

	private static final LogConsumer LOG = LogConsumerFactory.getTaggedConsumer("Client");

	private final int[] defaultCs;
	private final BcSecurityPrototype securityPrototype;
	private final String hostname;

	private TlsAuthentication authentication = null;

	public BcTlsClient(BcSecurityPrototype prototype, String host) {
		this.hostname = host;
		this.securityPrototype = prototype;
		this.defaultCs = CipherSuite.convert(this.securityPrototype.getCipherSuites());
	}

	@Override
	public int[] getCipherSuites() {
		return defaultCs;
	}

	@Override
	public void notifySelectedCipherSuite(int selectedCipherSuite) {
		try {
			this.securityPrototype.initialise(selectedCipherSuite);
			this.authentication = this.securityPrototype.makeAuthentication();

		} catch (IOException e) {
			LOG.error("There is no authentication available for this cipher suite", e);
		}

		this.selectedCipherSuite = selectedCipherSuite;
	}

	/**
	 * Get the cipher suite selected with the server hello message
	 * 
	 * @return the selected cipher suite
	 */
	public int getSelectedCipherSuite() {
		return this.selectedCipherSuite;

	}

	@Override
	public TlsAuthentication getAuthentication() throws IOException {
		return this.authentication;
	}

	@Override
	public ProtocolVersion getMinimumVersion() {
		return ProtocolVersion.TLSv12;
	}

}
