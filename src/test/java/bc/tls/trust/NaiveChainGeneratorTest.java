package bc.tls.trust;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.x509.util.StreamParsingException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import bc.tls.TestTools;

public class NaiveChainGeneratorTest {

	private static final FileSystem fs = FileSystems.getDefault();

	static final Path baseDir = fs.getPath("src", "test", "resources", "simpleChains");

	static final Path certDir = baseDir.resolve("certs");
	static final Path subCaDir = baseDir.resolve("subs");
	static final Path rootCaDir = baseDir.resolve("roots");

	static final String pattern4Links = "Subsub\\d.*";
	static final String pattern3Links = "Sub\\d.*";

	public static Collection<Path> getCertsFromDir(Path dir) {
		Collection<Path> paths = new HashSet<Path>();

		try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, "*.pem")) {
			stream.forEach(p -> paths.add(p));
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
		return paths;
	}

	private Collection<X509Certificate> certs;
	private int expectedChains;

	@Before
	public void prepare() throws IOException {
		Collection<Path> certPaths = getCertsFromDir(certDir);
		expectedChains = certPaths.size();
		certPaths.addAll(getCertsFromDir(subCaDir));
		certPaths.addAll(getCertsFromDir(rootCaDir));

		certs = new HashSet<X509Certificate>();

		for (Path path : certPaths) {
			certs.add(TestTools.loadCert(path.toFile()));
		}
	}

	@Test
	public void testing() throws IOException, StreamParsingException, CertificateException {
		NaiveChainGenerator gen = new NaiveChainGenerator();
		gen.init(certs);
		Collection<Certificate> chains = gen.generateChains();
		Assert.assertEquals("Unexpected number of chains", this.expectedChains, chains.size());

		for (Certificate chain : chains) {
			byte[] certBytes = chain.getCertificateAt(0).getEncoded();

			X509Certificate userCert;
			try (InputStream stream = new ByteArrayInputStream(certBytes)) {
				userCert = TestTools.loadCert(stream);
			}

			String commonName = TestTools.getCommonName(userCert);

			int expectedChainLength;
			if (commonName.matches(pattern4Links)) {
				expectedChainLength = 4;
			} else if (commonName.matches(pattern3Links)) {
				expectedChainLength = 3;
			} else {
				expectedChainLength = -1;
			}

			Assert.assertEquals("Unexpected length of chain", expectedChainLength, chain.getLength());

			checkChainIntegrity(chain);
		}

	}

	private void checkChainIntegrity(Certificate chain) {
		X500Name issuer = null;
		for (org.bouncycastle.asn1.x509.Certificate cert : chain.getCertificateList()) {
			if (issuer == null) {
				issuer = cert.getIssuer();
				System.out.println(issuer);
				continue;
			}

			Assert.assertEquals("Issuer does not match", issuer, cert.getSubject());
			issuer = cert.getIssuer();
		}
	}

}
