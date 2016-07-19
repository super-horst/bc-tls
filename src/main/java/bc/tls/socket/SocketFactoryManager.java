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

import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsCredentials;

import bc.tls.CipherSuite;

public interface SocketFactoryManager {
	/**
	 * Config property key for socket timeout
	 * <p>
	 * Accepts: {@link Integer}
	 */
	public static final String KEY_TIMEOUT = "bc.tls.socket.timeout";
	/**
	 * Default timeout in seconds
	 */
	public static final Integer DEFAULT_TIMEOUT = 10;
	/**
	 * Config property key for default cipher suites
	 * <p>
	 * Accepts: {@link String[]} and {@link CipherSuite}[]
	 */
	public static final String KEY_DEFAULT_CIPHER_SUITES = "bc.tls.ciphers.default";
	/**
	 * Config property key for supported cipher suites
	 * <p>
	 * Accepts: {@link String[]} and {@link CipherSuite}[]
	 */
	public static final String KEY_SUPPORTED_CIPHER_SUITES = "bc.tls.ciphers.supported";
	/**
	 * Config property key to close the underlying socket when this socket is
	 * closed
	 * <p>
	 * Accepts: {@link Boolean}
	 */
	public static final String KEY_SOCKET_AUTO_CLOSE = "bc.tls.socket.autoClose";
	/**
	 * Config property key for the default tls authentication object
	 * <p>
	 * Accepts: {@link TlsAuthentication}
	 */
	public static final String KEY_DEFAULT_AUTHENTICATION = "bc.tls.authentication.default";
	/**
	 * Config property key for the default tls credentials
	 * <p>
	 * Accepts: {@link TlsCredentials}
	 */
	public static final String KEY_DEFAULT_CREDENTIALS = "bc.tls.credentials.default";
	
	/**
	 * Set a configuration property.
	 * 
	 * @param key
	 *            property key
	 * @param value
	 *            the configuration value to set
	 */
	void setConfigProperty(final String key, final Object value);

	/**
	 * Get a configuration property.
	 * 
	 * @param key
	 *            property key
	 * @return the configuration value you are looking for ... or {@code null}
	 *         if there is no such property
	 */
	Object getConfigProperty(final String key);
}
