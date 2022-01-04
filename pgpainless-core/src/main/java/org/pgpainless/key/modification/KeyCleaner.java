// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.signature.SignatureFilter;

public class KeyCleaner {

    public static @Nonnull PGPPublicKeyRing filterThirdPartySignatures(@Nonnull PGPPublicKeyRing certificate) throws PGPException {
        List<PGPPublicKey> filteredKeys = new ArrayList<>();
        List<PGPPublicKey> keys = new ArrayList<>();
        Iterator<PGPPublicKey> keyIterator = certificate.getPublicKeys();
        while (keyIterator.hasNext()) {
            PGPPublicKey key = keyIterator.next();
            keys.add(key);
            PGPPublicKey filteredKey = filterSignatures(key,
                    SignatureFilter.rejectThirdPartySignatures(certificate));
            filteredKeys.add(filteredKey);
        }

        return new PGPPublicKeyRing(filteredKeys);
    }

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

        PGPPublicKey filteredKey = key;

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
                if (!signatureFilter.accept(signature)) {
                    filteredKey = PGPPublicKey.removeCertification(filteredKey, signature);
                }
            }
        }

        // User-ID certifications / revocations
        for (Iterator<String> it = key.getUserIDs(); it.hasNext(); ) {
            String userId = it.next();
            Iterator<PGPSignature> signatures = key.getSignaturesForID(userId);
            while (signatures.hasNext()) {
                PGPSignature signature = signatures.next();
                if (!signatureFilter.accept(signature)) {
                    filteredKey = PGPPublicKey.removeCertification(filteredKey, userId, signature);
                }
            }
        }

        // User-Attribute certifications / revocations
        for (Iterator<PGPUserAttributeSubpacketVector> it = key.getUserAttributes(); it.hasNext(); ) {
            PGPUserAttributeSubpacketVector attribute = it.next();
            Iterator<PGPSignature> signatures = key.getSignaturesForUserAttribute(attribute);
            while (signatures.hasNext()) {
                PGPSignature signature = signatures.next();
                if (!signatureFilter.accept(signature)) {
                    filteredKey = PGPPublicKey.removeCertification(filteredKey, attribute, signature);
                }
            }
        }

        return filteredKey;
    }
}
