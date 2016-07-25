package bc.tls.socket;

import java.util.HashSet;
import java.util.Set;

import org.junit.Assert;
import org.junit.Test;

import bc.tls.CipherSuite;

public class CipherSuiteTest {

	private static final CipherSuite[] suites = new CipherSuite[] {
			CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256,
			CipherSuite.TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA };

	private static final String[] suiteStrings = new String[suites.length];
	private static final int[] suiteInts = new int[suites.length];

	static {
		for (int i = 0; i < suites.length; i++) {
			suiteStrings[i] = suites[i].name();
			suiteInts[i] = suites[i].id();
		}
	}

	@Test
	public void stringConversionTest() {
		int[] convResult = CipherSuite.convert(suiteStrings);
		Assert.assertArrayEquals(suiteInts, convResult);
	}

	@Test
	public void intConversionTest() {
		String[] convResult = CipherSuite.convert(suiteInts);
		Assert.assertArrayEquals(suiteStrings, convResult);
	}

	@Test
	public void checkDoubleDefinition() {
		Set<Integer> suites = new HashSet<Integer>(CipherSuite.values().length);
		for (CipherSuite suite : CipherSuite.values()) {
			if (!suites.add(suite.id())) {
				throw new IllegalArgumentException("CipherSuite already exists: " + suite.name());
			}
		}
	}

	@Test
	public void checkEmptyBehaviour() {
		int[] intResult = CipherSuite.convert(new String[0]);
		Assert.assertNotNull(intResult);
		Assert.assertTrue(intResult.length == 0);

		String[] stringResult = CipherSuite.convert(new int[0]);
		Assert.assertNotNull(stringResult);
		Assert.assertTrue(stringResult.length == 0);

		String[] stringResult2 = CipherSuite.convert(new CipherSuite[0]);
		Assert.assertNotNull(stringResult2);
		Assert.assertTrue(stringResult2.length == 0);
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void checkNullIntBehaviour() {
		CipherSuite.convert((String[]) null);
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void checkNullStringBehaviour() {
		CipherSuite.convert((int[]) null);
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void checkNullCipherSuiteBehaviour() {
		CipherSuite.convert((CipherSuite[]) null);
	}

}
