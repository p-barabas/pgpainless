// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.merging;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;

public class CertificateMerger {

    public static PGPPublicKeyRing merge(PGPPublicKeyRing certificate, PGPPublicKeyRing updates) {
        return null;
    }

    public static PGPPublicKeyRing merge(PGPPublicKeyRing certificate, PGPSignature update) {
        return null;
    }
}
