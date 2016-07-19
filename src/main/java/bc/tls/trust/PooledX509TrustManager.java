package bc.tls.trust;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.X509TrustManager;

public class PooledX509TrustManager implements X509TrustManager {
	
	private final Set<X509Certificate> certPool;
	
	public PooledX509TrustManager(Collection<X509Certificate> certs) {
		this.certPool = new HashSet<X509Certificate>(certs);
	}
	
	public PooledX509TrustManager(X509Certificate[] certs) {
		this.certPool = new HashSet<X509Certificate>(Arrays.asList(certs));
	}
	
	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		isCertInPool(chain);
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		isCertInPool(chain);
	}

	private void isCertInPool(X509Certificate[] chain) throws CertificateException {
		boolean pooled = false;
		for (X509Certificate cert : chain) {
			pooled |= this.certPool.contains(cert);
		}
		
		if (! pooled) {
			throw new CertificateException("Certificates were not found in pool");
		}
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return certPool.toArray(new X509Certificate[certPool.size()]);
	}
}
