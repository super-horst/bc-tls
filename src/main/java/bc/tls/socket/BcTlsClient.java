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

import bc.tls.CipherSuite;

/**
 * BC-tls client
 * 
 * @author super-horst
 *
 */
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

}
