package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.signature.SignatureFilter;
import org.pgpainless.util.ArmorUtils;

public class KeyMinifierTest {

    private static final String ALICE_CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 5063 9AFD A521 71FD 03F6  9DFC A650 D1AC 999D F19E\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "mDMEYdCGzRYJKwYBBAHaRw8BAQdAgqRa8bRBQn2QBdf3JJCnN2xACRDwLrH8fu1/\n" +
            "QAFiSHO0HEFsaWNlIDxhbGljZUBwZ3BhaW5sZXNzLm9yZz6IjwQTFgoAQQUCYdCG\n" +
            "zQmQplDRrJmd8Z4WoQRQY5r9pSFx/QP2nfymUNGsmZ3xngKeAQKbAQWWAgMBAASL\n" +
            "CQgHBZUKCQgLApkBAAB0nwEAwom+cyTBLNNGNrlnwvuDOjrTKRcyZq7hBdGD15R4\n" +
            "LZsA/jAxL2rlVS6acdc5ZIHwUn2UPI5s+aJzGJxwuNdOW40JuDgEYdCGzRIKKwYB\n" +
            "BAGXVQEFAQEHQL5DW3ar3KbvKS5ubfMgvk3zO8dDISDdfToZAO2MsUR0AwEIB4h1\n" +
            "BBgWCgAdBQJh0IbNAp4BApsMBZYCAwEABIsJCAcFlQoJCAsACgkQplDRrJmd8Z58\n" +
            "KAD/YhooBDVc3BPmuv5+QU3ekUrQlLT2zFlOotnEgTHf2csBAIbYpIUiIDD/p1pR\n" +
            "knwRUxKjQexx31PYMb2oz0YwpUYEuDMEYdCGzRYJKwYBBAHaRw8BAQdADFVN87QI\n" +
            "NATo8DJ3YPklEs8INjAilYmAz2kWAUMNAfGI1QQYFgoAfQUCYdCGzQKeAQKbAgWW\n" +
            "AgMBAASLCQgHBZUKCQgLXyAEGRYKAAYFAmHQhs0ACgkQ5ChD8xd7sdWVaQEAyKUt\n" +
            "9WU+9zfFThBt79KfbE7GvalUEEM6Cl7W5SO+AZQBAKikUTQvo08ds0zQTSof/esq\n" +
            "L95XRyA/AqppElLa6GgEAAoJEKZQ0ayZnfGe6LwA/RmspoCbMo5ZpvBnYgo0t7YM\n" +
            "qae55btn5bLiBDnXhvVXAPsHBdZ8iYwDTa6HTB7IgM0KFejmRe2QrEbX46LYMZjk\n" +
            "Aw==\n" +
            "=iERs\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";
    private static final String BOB_CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 718B BA02 190A 08F9 1716  AB51 DA16 1EEE 183E 7043\n" +
            "Comment: Bob <bob@pgpainless.org>\n" +
            "\n" +
            "mDMEYdCGzRYJKwYBBAHaRw8BAQdA6+ons2q4EAZNJBk5K9n4ZCkKbSdZ4/g5Lo+n\n" +
            "X49ljtC0GEJvYiA8Ym9iQHBncGFpbmxlc3Mub3JnPoiPBBMWCgBBBQJh0IbNCZDa\n" +
            "Fh7uGD5wQxahBHGLugIZCgj5FxarUdoWHu4YPnBDAp4BApsBBZYCAwEABIsJCAcF\n" +
            "lQoJCAsCmQEAALSiAP0e+f6sx5BqWUVKJ6R75iC5RsTtL6gggOcY3eX6T4J46QEA\n" +
            "690+KrN49fD+3vu50QBkdKcDlQrrJ7BwTul2GVMrQg64OARh0IbNEgorBgEEAZdV\n" +
            "AQUBAQdA2mliFdl0zTVbI5jjg9QYTi9GEmEM3v2NxL8VqmdiyEEDAQgHiHUEGBYK\n" +
            "AB0FAmHQhs0CngECmwwFlgIDAQAEiwkIBwWVCgkICwAKCRDaFh7uGD5wQwZ7AP4n\n" +
            "IPbIGTD6b4Soc2vKq5fp7Y1ghas/gkSFZEF8FmqPzwEA2Je3hgLj0djJkSAi+3ol\n" +
            "8e2iECWc2idwDPmzY/o+GQK4MwRh0IbNFgkrBgEEAdpHDwEBB0DYR+yWTjU0ZHsN\n" +
            "l/RFS3hhIsPT0cxvEfLrQZnUwFMpu4jVBBgWCgB9BQJh0IbNAp4BApsCBZYCAwEA\n" +
            "BIsJCAcFlQoJCAtfIAQZFgoABgUCYdCGzQAKCRCQu6pUT0Zt4ZsLAP9kf4/GpGV7\n" +
            "X6nZYRuz3kgn6Mb5kLfRDGYa70rSgrZS3QD+MLg5WBi6xvdaKGrobuzHM0Kjh7l8\n" +
            "AS3tuyNhnf2hlQ0ACgkQ2hYe7hg+cEMU1QD+KRtVfLOQCz8VYogn1gQAE0aTIqWr\n" +
            "ffrY6ZvoQNUhDK4A/j08wj4F/LQowcJG43m3UyWKOmL0TN5bH5rVwKWaTJQG\n" +
            "=EsCN\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";
    private static final String BOB_CERT_WITH_ALICE_CERTIFICATION = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 718B BA02 190A 08F9 1716  AB51 DA16 1EEE 183E 7043\n" +
            "Comment: Bob <bob@pgpainless.org>\n" +
            "\n" +
            "mDMEYdCGzRYJKwYBBAHaRw8BAQdA6+ons2q4EAZNJBk5K9n4ZCkKbSdZ4/g5Lo+n\n" +
            "X49ljtC0GEJvYiA8Ym9iQHBncGFpbmxlc3Mub3JnPoiPBBMWCgBBBQJh0IbNCZDa\n" +
            "Fh7uGD5wQxahBHGLugIZCgj5FxarUdoWHu4YPnBDAp4BApsBBZYCAwEABIsJCAcF\n" +
            "lQoJCAsCmQEAALSiAP0e+f6sx5BqWUVKJ6R75iC5RsTtL6gggOcY3eX6T4J46QEA\n" +
            "690+KrN49fD+3vu50QBkdKcDlQrrJ7BwTul2GVMrQg6IdQQQFgoAJwUCYdCGzQmQ\n" +
            "plDRrJmd8Z4WoQRQY5r9pSFx/QP2nfymUNGsmZ3xngAAG70A+wZYGjXDGED+E596\n" +
            "r+HcqR3DE+YYNmHn0IGyckJ/v5jcAP9QPkuhPM+7u1VwE6KlUlIJ3+tIHK6GEwPp\n" +
            "jkLD3GvnBrg4BGHQhs0SCisGAQQBl1UBBQEBB0DaaWIV2XTNNVsjmOOD1BhOL0YS\n" +
            "YQze/Y3EvxWqZ2LIQQMBCAeIdQQYFgoAHQUCYdCGzQKeAQKbDAWWAgMBAASLCQgH\n" +
            "BZUKCQgLAAoJENoWHu4YPnBDBnsA/icg9sgZMPpvhKhza8qrl+ntjWCFqz+CRIVk\n" +
            "QXwWao/PAQDYl7eGAuPR2MmRICL7eiXx7aIQJZzaJ3AM+bNj+j4ZArgzBGHQhs0W\n" +
            "CSsGAQQB2kcPAQEHQNhH7JZONTRkew2X9EVLeGEiw9PRzG8R8utBmdTAUym7iNUE\n" +
            "GBYKAH0FAmHQhs0CngECmwIFlgIDAQAEiwkIBwWVCgkIC18gBBkWCgAGBQJh0IbN\n" +
            "AAoJEJC7qlRPRm3hmwsA/2R/j8akZXtfqdlhG7PeSCfoxvmQt9EMZhrvStKCtlLd\n" +
            "AP4wuDlYGLrG91ooauhu7MczQqOHuXwBLe27I2Gd/aGVDQAKCRDaFh7uGD5wQxTV\n" +
            "AP4pG1V8s5ALPxViiCfWBAATRpMipat9+tjpm+hA1SEMrgD+PTzCPgX8tCjBwkbj\n" +
            "ebdTJYo6YvRM3lsfmtXApZpMlAY=\n" +
            "=WZ7v\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";

    @Test
    public void testMinificationByRemovalOfThirdPartySigs() throws PGPException, IOException {
        PGPPublicKeyRing bobCert = PGPainless.readKeyRing().publicKeyRing(BOB_CERT_WITH_ALICE_CERTIFICATION);

        PGPPublicKey bobsSignedPrimaryKey = bobCert.getPublicKey();

        final PGPPublicKeyRing finalBobCert = bobCert;
        PGPPublicKey bobsCleanedPrimaryKey = Minifier.filterSignatures(bobsSignedPrimaryKey, new SignatureFilter() {
            @Override
            public boolean accept(PGPSignature signature) {
                // Quick, unsafe way of checking if sig was made by some of bobs keys
                return finalBobCert.getPublicKey(signature.getKeyID()) != null;
            }
        });

        bobCert = PGPPublicKeyRing.insertPublicKey(bobCert, bobsCleanedPrimaryKey);

        assertEquals(ArmorUtils.toAsciiArmoredString(bobCert), BOB_CERT);
    }
}
