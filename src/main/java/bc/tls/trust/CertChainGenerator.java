package bc.tls.trust;

import java.security.cert.X509Certificate;
import java.util.Collection;

import org.bouncycastle.crypto.tls.Certificate;

public interface CertChainGenerator {

	void initialise(Collection<X509Certificate> certificates);

	Collection<Certificate> resolveToChain();

}
