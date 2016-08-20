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
package bc.tls;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;
import org.bouncycastle.util.Arrays;

public class DefaultSecurityPrototype implements BcSecurityPrototype {

	private final CipherSuite[] enabledCipherSuites;
	private CipherSuite selectedCipherSuite = null;

	public DefaultSecurityPrototype(Void keys, Void certs, Void[] keyExchanges, Void[] hashAlgos) {

		this.enabledCipherSuites = assembleCipherSuites();
	}

	private CipherSuite[] assembleCipherSuites() {
		// TODO Auto-generated method stub
		return new CipherSuite[0];
	}

	@Override
	public String[] getCipherSuites() {
		return CipherSuite.convert(this.enabledCipherSuites);
	}

	@Override
	public SecureRandom makeRandom() {
		return new SecureRandom();
	}

	@Override
	public void initialise(int cipherSuite) throws IOException {
		CipherSuite suite = CipherSuite.lookup(cipherSuite);

		if (suite == null) {
			throw new IOException("Cipher suite cannot be resolved: " + cipherSuite);
		}

		int[] enabledSuites = CipherSuite.convert(CipherSuite.convert(this.enabledCipherSuites));
		if (!Arrays.contains(enabledSuites, cipherSuite)) {
			throw new IOException("Cipher suite not supported: " + suite);
		}

		this.selectedCipherSuite = suite;
	}

	@Override
	public TlsAuthentication makeAuthentication() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public TlsSignerCredentials makeSignerCredentials() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public TlsCredentials makeCredentials() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CertificateRequest makeCertificateRequest() {
		// TODO Auto-generated method stub
		return null;
	}
}
