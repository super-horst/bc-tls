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
import java.security.SecureRandom;

import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;

/**
 * Security prototype to resolve the selected cipher suite to tls security
 * parameters.
 * 
 * @author super-horst
 *
 */
public interface BcSecurityPrototype {

	/**
	 * @return all supported cipher suites
	 */
	String[] getCipherSuites();

	SecureRandom makeRandom();

	/**
	 * Initialising the prototype
	 * 
	 * @param cipherSuite
	 *            the selected cipher suite
	 * @throws IOException
	 *             thrown if the selected cipher suite is not supported
	 */
	void initialise(int cipherSuite) throws IOException;

	/**
	 * Creates tls authentication for the selected cipher suite
	 * 
	 * @return a {@link TlsAuthentication} object or {@code null} if there is no
	 *         supported authentication
	 */
	TlsAuthentication makeAuthentication();

	/**
	 * Creates tls signer credentials for the selected cipher suite
	 * 
	 * @return a {@link TlsSignerCredentials} object or {@code null} if there
	 *         are no supported credentials
	 */
	TlsSignerCredentials makeSignerCredentials();

	/**
	 * Creates tls credentials for the selected cipher suite
	 * 
	 * @return a {@link TlsCredentials} object or {@code null} if there are no
	 *         supported credentials
	 * 
	 * @deprecated
	 */
	TlsCredentials makeCredentials();

	CertificateRequest makeCertificateRequest();

}