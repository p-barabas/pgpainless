// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class OpenPgpV5FingerprintTest {

    @Test
    public void testFingerprintFormatting() {
        String pretty = "76543210 ABCDEFAB 01AB23CD 1C0FFEE1  1EEFF0C1 DC32BA10 BAFEDCBA 01234567";
        String fp = pretty.replace(" ", "");

        OpenPgpV5Fingerprint fingerprint = new OpenPgpV5Fingerprint(fp);
        assertEquals(fp, fingerprint.toString());
        assertEquals(pretty, fingerprint.prettyPrint());

        long id = fingerprint.getKeyId();
        assertEquals("76543210abcdefab", Long.toHexString(id));
    }

    @Test
    public void testParse() {
        String prettyPrint = "76543210 ABCDEFAB 01AB23CD 1C0FFEE1  1EEFF0C1 DC32BA10 BAFEDCBA 01234567";
        OpenPgpFingerprint parsed = OpenPgpFingerprint.parse(prettyPrint);

        assertTrue(parsed instanceof OpenPgpV5Fingerprint);
        OpenPgpV5Fingerprint v5fp = (OpenPgpV5Fingerprint) parsed;
        assertEquals(prettyPrint, v5fp.prettyPrint());
    }
}
