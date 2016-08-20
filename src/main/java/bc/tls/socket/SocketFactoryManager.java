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

import java.util.concurrent.TimeUnit;

import bc.tls.BcSecurityPrototype;

/**
 * Manager interface with some methods to configure socket factories.
 * 
 * Keys for the {@code ConfigProperty} methods are located here.
 * 
 * @author super-horst
 *
 */
public interface SocketFactoryManager {
	/**
	 * Default timeout in seconds
	 */
	public static final Long DEFAULT_TIMEOUT = 10L;
	/**
	 * Config property key to close the underlying socket when the tls socket is
	 * closed
	 * <p>
	 * Accepts: {@link Boolean}
	 */
	public static final String KEY_SOCKET_AUTO_CLOSE = "bc.tls.socket.autoClose";
	/**
	 * Config property key for an optional random provider
	 * <p>
	 * Accepts: {@link String} and {@link Provider}
	 * 
	 * @deprecated
	 */
	public static final String KEY_RANDOM_PROVIDER = "bc.tls.random.provider";
	/**
	 * Config property key for an optional random algorithm
	 * <p>
	 * Accepts: {@link String}
	 * 
	 * @deprecated
	 */
	public static final String KEY_RANDOM_ALGORITHM = "bc.tls.random.algorithm";

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

	/**
	 * Set this factories default timeout
	 * 
	 * @param timeout
	 *            the timeout value
	 * @param unit
	 *            given values unit
	 */
	void setDefaultTimeout(Long timeout, TimeUnit unit);

	/**
	 * @return this factory's default timeout (in milliseconds)
	 */
	Long getDefaultTimeout();

	/**
	 * Set the default cipher suites
	 * 
	 * @param suites
	 *            cipher suites to set
	 */
	@Deprecated
	void setDefaultCipherSuites(String[] suites);

	/**
	 * Set the supported cipher suites
	 * 
	 * @param suites
	 *            cipher suites to set
	 */
	@Deprecated
	void setSupportedCipherSuites(String[] suites);

	/**
	 * @return this factory's default security prototype
	 */
	BcSecurityPrototype getDefaultSecurityPrototype();

	/**
	 * Update this factory's default security prototype
	 * 
	 * @param prototype
	 *            this factory's new default security prototype
	 */
	public void setDefaultSecurityPrototype(BcSecurityPrototype prototype);
}
