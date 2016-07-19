package bc.tls.socket;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.channels.SocketChannel;

import javax.net.ssl.SSLSocket;

/**
 * Abstract base class to handle the wrapped raw socket.
 * 
 * @author freddy.curium
 * 
 */
public abstract class AbstractBcTlsSocket extends SSLSocket {
	private final Object closeLock = new Object();
	private final boolean autoClose;
	private boolean closed = false;

	protected final Socket socket;

	/**
	 * @param rawSocket
	 *            the socket to manage
	 * @param autoClose
	 *            wheter to close to socket on close of parent
	 */
	public AbstractBcTlsSocket(Socket rawSocket, boolean autoClose) {
		this.socket = rawSocket;
		this.autoClose = autoClose;
	}

	@Override
	public synchronized void close() throws IOException {
		synchronized (closeLock) {
			if (isClosed()) {
				return;
			}
			if (autoClose) {
				this.socket.close();
			}
			closed = true;
		}
	}

	@Override
	public boolean isClosed() {
		synchronized (closeLock) {
			return closed;
		}
	}

	@Override
	public InetAddress getInetAddress() {
		return this.socket.getInetAddress();
	}

	@Override
	public InetAddress getLocalAddress() {
		return this.socket.getLocalAddress();
	}

	@Override
	public int getPort() {
		return this.socket.getPort();
	}

	@Override
	public int getLocalPort() {
		return this.socket.getLocalPort();
	}

	@Override
	public SocketAddress getRemoteSocketAddress() {
		return this.socket.getRemoteSocketAddress();
	}

	@Override
	public SocketAddress getLocalSocketAddress() {
		return this.socket.getLocalSocketAddress();
	}

	@Override
	public SocketChannel getChannel() {
		// TODO implement!
		return null;
	}
}
