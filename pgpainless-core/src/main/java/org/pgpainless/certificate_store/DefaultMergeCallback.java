// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.certificate_store;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.pgpainless.PGPainless;
import pgp.certificate_store.Certificate;
import pgp.certificate_store.MergeCallback;

public class DefaultMergeCallback implements MergeCallback {

    @Override
    public Certificate merge(Certificate data, Certificate existing) throws IOException {
        // no existing certificate
        if (existing == null) {
            return data;
        }

        if (!data.getFingerprint().equals(existing.getFingerprint())) {
            throw new IllegalArgumentException("Certificate mismatch! " +
                    "Existing certificate: " + existing.getFingerprint() + ", New certificate: " + data.getFingerprint());
        }

        // existing and new certificates are equal
        if (existing.getTag().equals(data.getTag())) {
            return existing;
        }

        PGPPublicKeyRing existingCertificate = PGPainless.readKeyRing().publicKeyRing(existing.getInputStream());
        PGPPublicKeyRing updatedCertificate = PGPainless.readKeyRing().publicKeyRing(data.getInputStream());

        List<PGPPublicKey> mergedKeys = new ArrayList<>();

        for (PGPPublicKey key : existingCertificate) {
            PGPPublicKey kay = updatedCertificate.getPublicKey(key.getKeyID());
            if (kay != null) {
                // TODO: get https://github.com/bcgit/bc-java/pull/1102 merged
                PGPPublicKey mkay = PGPPublicKey.join(key, kay);
                mergedKeys.add(mkay);
            } else {
                mergedKeys.add(key);
            }
        }

        for (PGPPublicKey key : updatedCertificate) {
            PGPPublicKey kay = existingCertificate.getPublicKey(key.getKeyID());
            if (kay == null) {
                mergedKeys.add(key);
            }
        }

        PGPPublicKeyRing merged = new PGPPublicKeyRing(mergedKeys);
        return CertificateFactory.certificateFromPublicKeyRing(merged);
    }

}
