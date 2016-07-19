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
