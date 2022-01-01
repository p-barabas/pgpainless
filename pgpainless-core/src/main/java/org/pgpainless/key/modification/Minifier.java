// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import java.util.Arrays;
import java.util.Iterator;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.signature.SignatureFilter;

public class Minifier {

    /**
     * Return a copy of the passed in key, containing only signatures that pass the given signatureFilter.
     *
     * @param key key
     * @param signatureFilter filter
     * @return filtered key
     * @throws PGPException if no copy of the key can be created (not expected to happen)
     */
    public static @Nonnull PGPPublicKey filterSignatures(@Nonnull PGPPublicKey key, @Nonnull SignatureFilter signatureFilter)
            throws PGPException {
        PGPPublicKey newKey = new PGPPublicKey(key.getPublicKeyPacket(), ImplementationFactory.getInstance().getKeyFingerprintCalculator());

        // Key Signatures
        for (SignatureType type : Arrays.asList(
                SignatureType.DIRECT_KEY,
                SignatureType.KEY_REVOCATION,
                SignatureType.SUBKEY_BINDING,
                SignatureType.SUBKEY_REVOCATION)
        ) {
            Iterator<PGPSignature> iterator = key.getSignaturesOfType(type.getCode());
            while (iterator.hasNext()) {
                PGPSignature signature = iterator.next();
                if (signatureFilter.accept(signature)) {
                    newKey = PGPPublicKey.addCertification(newKey, signature);
                }
            }
        }

        // User-ID certifications / revocations
        for (Iterator<String> it = key.getUserIDs(); it.hasNext(); ) {
            String userId = it.next();
            Iterator<PGPSignature> signatures = key.getSignaturesForID(userId);
            while (signatures.hasNext()) {
                PGPSignature signature = signatures.next();
                if (signatureFilter.accept(signature)) {
                    newKey = PGPPublicKey.addCertification(newKey, userId, signature);
                }
            }
        }

        // User-Attribute certifications / revocations
        for (Iterator<PGPUserAttributeSubpacketVector> it = key.getUserAttributes(); it.hasNext(); ) {
            PGPUserAttributeSubpacketVector attribute = it.next();
            Iterator<PGPSignature> signatures = key.getSignaturesForUserAttribute(attribute);
            while (signatures.hasNext()) {
                PGPSignature signature = signatures.next();
                if (signatureFilter.accept(signature)) {
                    newKey = PGPPublicKey.addCertification(newKey, attribute, signature);
                }
            }
        }

        return newKey;
    }
}
