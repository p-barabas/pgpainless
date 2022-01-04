// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature;

import javax.annotation.Nonnull;

import org.bouncycastle.bcpg.sig.RevocationKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;

public abstract class SignatureFilter {

    public abstract boolean accept(PGPSignature signature);

    public static @Nonnull SignatureFilter and(@Nonnull SignatureFilter filter, @Nonnull SignatureFilter... filters) {
        return new SignatureFilter() {
            @Override
            public boolean accept(PGPSignature signature) {
                if (!filter.accept(signature)) {
                    return false;
                }

                for (SignatureFilter other : filters) {
                    if (!other.accept(signature)) {
                        return false;
                    }
                }

                return true;
            }
        };
    }

    public static @Nonnull SignatureFilter or(@Nonnull SignatureFilter filter, @Nonnull SignatureFilter... filters) {
        return new SignatureFilter() {
            @Override
            public boolean accept(PGPSignature signature) {
                if (filter.accept(signature)) {
                    return true;
                }

                for (SignatureFilter other : filters) {
                    if (other.accept(signature)) {
                        return true;
                    }
                }

                return false;
            }
        };
    }

    public static @Nonnull SignatureFilter not(@Nonnull SignatureFilter filter) {
        return new SignatureFilter() {
            @Override
            public boolean accept(PGPSignature signature) {
                return !filter.accept(signature);
            }
        };
    }

    public static @Nonnull SignatureFilter rejectThirdPartySignatures(
            @Nonnull PGPPublicKeyRing certificate) {
        return or(
                rejectSignaturesByExternalKey(certificate), // sig by us
                rejectRevocationsFromNonRevocationKeys(certificate) // external sig, but by legal revocation key
        );
    }

    /**
     * Reject signatures made by a key not on the passed in certificate.
     * This method does only compare the key-id, it does not perform any sanity checks on the signature.
     *
     * @param certificate certificate
     * @return signature filter
     */
    private static @Nonnull SignatureFilter rejectSignaturesByExternalKey(@Nonnull PGPPublicKeyRing certificate) {
        return new SignatureFilter() {
            @Override
            public boolean accept(PGPSignature signature) {
                KeyRingInfo info = KeyRingInfo.evaluateForSignature(certificate, signature);
                if (info.getPublicKey(signature.getKeyID()) == null) {
                    return false;
                }

                return true;
            }
        };
    }

    private static @Nonnull SignatureFilter rejectRevocationsFromNonRevocationKeys(@Nonnull PGPPublicKeyRing certificate) {
        return new SignatureFilter() {
            @Override
            public boolean accept(PGPSignature signature) {
                if (!SignatureType.isRevocationSignature(signature.getSignatureType())) {
                    return false;
                }

                KeyRingInfo info = KeyRingInfo.evaluateForSignature(certificate, signature);
                for (String userId : info.getUserIds()) {
                    PGPSignature certification = info.getLatestUserIdCertification(userId);

                    RevocationKey revocationKey = SignatureSubpacketsUtil.getRevocationKey(certification);
                    if (revocationKey == null) {
                        continue;
                    }

                    if (SignatureUtils.wasIssuedBy(revocationKey.getFingerprint(), signature)) {
                        return true;
                    }
                }

                PGPSignature directKeySig = info.getLatestDirectKeySelfSignature();
                if (directKeySig == null) {
                    return false;
                }

                RevocationKey revocationKey = SignatureSubpacketsUtil.getRevocationKey(directKeySig);
                if (revocationKey != null) {
                    return SignatureUtils.wasIssuedBy(revocationKey.getFingerprint(), signature);
                }

                return false;
            }
        };
    }
}
