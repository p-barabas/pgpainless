// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.io.IOException;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.util.TestAllImplementations;

public class OldSignatureSubpacketsArePreservedOnNewSig {

    private static final String nonExpiringKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 4398 3833 6CCB 85C4 BB5A  9E3A 1D0A 4A95 635B EE3F\n" +
            "Comment: Alice <alice@wonderland.lit>\n" +
            "\n" +
            "lFgEYdDrURYJKwYBBAHaRw8BAQdAKQ9V1m76/9Nh9Je2b69yznCeT31Sjl4MzV3E\n" +
            "q9/v014AAP9EEWaTbaUrmQWeoh/kclIOTOd/b6r4cFcFx2vOdFzUxxA3tBxBbGlj\n" +
            "ZSA8YWxpY2VAd29uZGVybGFuZC5saXQ+iI8EExYKAEEFAmHQ61IJkB0KSpVjW+4/\n" +
            "FqEEQ5g4M2zLhcS7Wp46HQpKlWNb7j8CngECmwMFlgIDAQAEiwkIBwWVCgkICwKZ\n" +
            "AQAAT+4A/2LrJ4O1f7npnE3vGemysXNkAb/h1XuiyIzspLJwjIyaAP97vn/n6xuJ\n" +
            "0bk78ZLEJE7IurNjuhb5xmREa68AYcmUAZxdBGHQ61ISCisGAQQBl1UBBQEBB0AN\n" +
            "tuRI87tPfJbKmXGGwbOjspLQ3qhFEKohaqeDmFe7OQMBCAcAAP976zWucXZ100RR\n" +
            "8KsjFGgO50O9TQ5f4adi2N41zTUrOBAviHUEGBYKAB0FAmHQ61ICngECmwwFlgID\n" +
            "AQAEiwkIBwWVCgkICwAKCRAdCkqVY1vuP/LEAQDg/K1bmNdpQdkPrZD00r55HP9T\n" +
            "vvExdYJtFaX2rCIANgEAidfP0vSG/17L6iDR3/TQC0qWew/iQaRhE95ALUn38g0=\n" +
            "=mNne\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void verifyOldSignatureSubpacketsArePreservedOnNewExpirationDateSig()
            throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(nonExpiringKey);

        PGPSignature oldSignature = PGPainless.inspectKeyRing(secretKeys).getLatestUserIdCertification("Alice <alice@wonderland.lit>");
        PGPSignatureSubpacketVector oldPackets = oldSignature.getHashedSubPackets();

        // key does not expire
        assertEquals(0, oldPackets.getKeyExpirationTime());

        Date now = new Date();
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(now);
        calendar.add(Calendar.DATE, 5);
        Date expiration = calendar.getTime(); // in 5 days

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(expiration, new UnprotectedKeysProtector())
                .done();
        PGPSignature newSignature = PGPainless.inspectKeyRing(secretKeys).getLatestUserIdCertification("Alice <alice@wonderland.lit>");
        PGPSignatureSubpacketVector newPackets = newSignature.getHashedSubPackets();

        assertNotEquals(0, newPackets.getKeyExpirationTime());

        assertArrayEquals(oldPackets.getPreferredHashAlgorithms(), newPackets.getPreferredHashAlgorithms());
    }
}
