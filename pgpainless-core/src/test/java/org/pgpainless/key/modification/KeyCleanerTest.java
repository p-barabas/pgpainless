// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.signature.SignatureFilter;

public class KeyCleanerTest {

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

    public static final String EXTERNAL_REVOCATION__REVOCATION_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: D0D1 B13D 8BB6 852C 213A  5549 2C52 E85E EED5 E82A\n" +
            "Comment: Alice Revocation Key\n" +
            "\n" +
            "lFgEYdRwyhYJKwYBBAHaRw8BAQdAPC+dFOyKFSBy7Qz2awGPU+vIrX5hBadnrG8N\n" +
            "zG3NfrwAAP0WSo5Kn0aQtM7h+8rGpwBo3szsaH7CRD+Gaqp8Q24F2RINtBRBbGlj\n" +
            "ZSBSZXZvY2F0aW9uIEtleYiPBBMWCgBBBQJh1HDKCZAsUuhe7tXoKhahBNDRsT2L\n" +
            "toUsITpVSSxS6F7u1egqAp4BApsBBZYCAwEABIsJCAcFlQoJCAsCmQEAACf9APwK\n" +
            "Gmei73KQT4/z76d/5WuYGxKAOPog/Hz2VAc0jzqzDwEA62lXYaxcBHJn+uHoOG7T\n" +
            "oiX2aQnne4iIYcWmOgvY4QycXQRh1HDKEgorBgEEAZdVAQUBAQdATRTv5UOhlt4f\n" +
            "fT/PhEugmWVP0XQfhaSM+kzbwN/Xm2cDAQgHAAD/S3osE7TaXrXptLoryqSMY1Cf\n" +
            "k7oEwnPbv9FC7Oei09ATvYh1BBgWCgAdBQJh1HDKAp4BApsMBZYCAwEABIsJCAcF\n" +
            "lQoJCAsACgkQLFLoXu7V6Cp5NgD/Y7g7/xYuezpDL7Coqmeu6u5XvYKms5UlcZD/\n" +
            "b+uhiw4BALx3vGXtJrsbMwHrM0Ecw8fOA9SH2/DsOwmUSLLjFlsOnFgEYdRwyhYJ\n" +
            "KwYBBAHaRw8BAQdAvFlxtUwZvzIqSfkcJPZijjIMNChFZlTuk5DhDAuqoAMAAPsH\n" +
            "M9DfDGjPW6+XvS9MTTvQlk4BcqiGP1FEYpuaYsnzmhAAiNUEGBYKAH0FAmHUcMoC\n" +
            "ngECmwIFlgIDAQAEiwkIBwWVCgkIC18gBBkWCgAGBQJh1HDKAAoJEPuFmxKUmdnK\n" +
            "C8UA/jREUb1KkvEIhs4bdYZebRsXoMfzInrn1E//kLZP8xLGAP9R8VuQDKIZd4Q6\n" +
            "/DXNcPu7z6Wc75PEvexXk7cEGBX3AAAKCRAsUuhe7tXoKnvIAP9tOz8dckunUWF+\n" +
            "KLYPTTXDnHce4VLxNSVOVPor9B9ktAD/doKezBSzrGtqt9/3TTbsu5VJ9i2ZORNB\n" +
            "6OfztujPTwc=\n" +
            "=EJqs\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";
    public static final String EXTERNAL_REVOCATION__REVOKED_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 2204 7599 9369 DD73 6A62  E639 D801 10F1 B00F 90BB\n" +
            "Comment: Alice Key\n" +
            "\n" +
            "lFgEYdRwyhYJKwYBBAHaRw8BAQdA6qzPVBbQjKapdfbFqE2Cnt4TEtqk6E1DXYQP\n" +
            "pnr5fEYAAQDah6jv5E31ez3aspY65vYrXFeuTZluGN6Fbk5QbiWmiRE4iI0EHxYK\n" +
            "AD8FAmHUcMoJkNgBEPGwD5C7FqEEIgR1mZNp3XNqYuY52AEQ8bAPkLsXjIAW0NGx\n" +
            "PYu2hSwhOlVJLFLoXu7V6CoAAJQOAP9rnCbUZhD8HDi9zLmHxSOwSZ/vebG4SYED\n" +
            "bbZ6V9f5qwD9GShXPH/S2dKwuXleJw58wtvjOYyFCXreJVmGKDNHKwSIewQgFgoA\n" +
            "LQUCYdRwygmQLFLoXu7V6CoWoQTQ0bE9i7aFLCE6VUksUuhe7tXoKgKHAAKdAwAA\n" +
            "kX0BAJuN0LJ5Lxyx773/HuzOR4CFfBE2fZSJ+P49EyLnLMpvAP9H5SlYTCEq7zgK\n" +
            "N9bNBIagRdkR7zs+z6uboyjsu9T/ArQJQWxpY2UgS2V5iI8EExYKAEEFAmHUcMoJ\n" +
            "kNgBEPGwD5C7FqEEIgR1mZNp3XNqYuY52AEQ8bAPkLsCngECmwEFlgIDAQAEiwkI\n" +
            "BwWVCgkICwKZAQAAyLcBANS9fjJMlrx7TAnhiLmgd5taYdQ9IfvI9X1kgaoMhim0\n" +
            "AQD4TQngO5VoujJnYNKcUVsk9buYxWBuJ7JY6HkjUM5gCZxdBGHUcMoSCisGAQQB\n" +
            "l1UBBQEBB0C6Wg/BwY4DWyRhG+aqCRAjJpFr7OKqli8BrOzz2TgaFAMBCAcAAP9w\n" +
            "rL0iSxIGivqRIltn5HhT/2zcptkVKKDvVptjCmAsIA+hiHUEGBYKAB0FAmHUcMoC\n" +
            "ngECmwwFlgIDAQAEiwkIBwWVCgkICwAKCRDYARDxsA+Qu7tZAP928VFCnN64PyFr\n" +
            "tkV7VoEX+v4JmMnSjiRKlnB4ZCTccwD9EEczALfgB61YZ4EqOC70x4KzwKMWQXG/\n" +
            "qRvnB/72XQecWARh1HDKFgkrBgEEAdpHDwEBB0D2ULcyNJo2DjjapnC9zS9Qa9Rp\n" +
            "TYEu0Kwy4qFD+Y8XFwAA/1vhpk+/2EXctP9bgd4fA/Bu9KTgzFKFiLwlAO90K7NH\n" +
            "EuGI1QQYFgoAfQUCYdRwygKeAQKbAgWWAgMBAASLCQgHBZUKCQgLXyAEGRYKAAYF\n" +
            "AmHUcMoACgkQ/VEQxA8tdFf5fQEApz5zynVmb/mbK62yYTE4Z8HjfyIzhqxJp+Wp\n" +
            "Xmi3A8ABAI1/8pGiP+3+Uw5v8r4Adh1KlCq1pM01qjxqN2O5KUIMAAoJENgBEPGw\n" +
            "D5C7EacA/3esnaCSv+qNcWQMk6iRUoVJhzqhODlz/VLGYnVeyFARAPwPuyGRUOgQ\n" +
            "FU0mpQR8D4hmS6eNcvSTRDe3sLahhKFRAA==\n" +
            "=S/04\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    @Test
    public void testMinificationByRemovalOfThirdPartySigs() throws PGPException, IOException {
        PGPPublicKeyRing bobCert = PGPainless.readKeyRing()
                .publicKeyRing(BOB_CERT_WITH_ALICE_CERTIFICATION);

        PGPPublicKey bobsSignedPrimaryKey = bobCert.getPublicKey();

        PGPPublicKey bobsCleanedPrimaryKey = KeyCleaner.filterSignatures(bobsSignedPrimaryKey, SignatureFilter.rejectThirdPartySignatures(bobCert));
        bobCert = PGPPublicKeyRing.insertPublicKey(bobCert, bobsCleanedPrimaryKey);

        assertArrayEquals(bobCert.getEncoded(), PGPainless.readKeyRing().publicKeyRing(BOB_CERT).getEncoded());
    }

    @Test
    public void testMinifyFreshKeyDoesNotChange()
            throws PGPException, IOException {
        PGPPublicKeyRing certificate = PGPainless.readKeyRing().publicKeyRing(ALICE_CERT);

        PGPPublicKeyRing cleaned = KeyCleaner.filterThirdPartySignatures(certificate);

        assertArrayEquals(certificate.getEncoded(), cleaned.getEncoded());
    }

    @Test
    public void testRevocationByRevocationKeyIsNotRemoved() throws IOException, PGPException {
        PGPSecretKeyRing revocationKey = PGPainless.readKeyRing().secretKeyRing(EXTERNAL_REVOCATION__REVOCATION_KEY);
        PGPSecretKeyRing revokedKey = PGPainless.readKeyRing().secretKeyRing(EXTERNAL_REVOCATION__REVOKED_KEY);

        PGPPublicKeyRing revokedCert = PGPainless.extractCertificate(revokedKey);

        PGPPublicKeyRing cleanedCert = KeyCleaner.filterThirdPartySignatures(revokedCert);

        assertArrayEquals(revokedCert.getEncoded(), cleanedCert.getEncoded());
    }
}
