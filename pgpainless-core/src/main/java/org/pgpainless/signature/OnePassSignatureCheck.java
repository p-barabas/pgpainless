/*
 * Copyright 2020 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.signature;

import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.SubkeyIdentifier;

/**
 * Tuple-class that bundles together a {@link PGPOnePassSignature} object, a {@link PGPPublicKeyRing}
 * destined to verify the signature, the {@link PGPSignature} itself and a record of whether the signature
 * was verified.
 */
public class OnePassSignatureCheck {
    private final PGPOnePassSignature onePassSignature;
    private final PGPPublicKeyRing verificationKeys;
    private PGPSignature signature;

    /**
     * Create a new {@link OnePassSignatureCheck}.
     *
     * @param onePassSignature one-pass signature packet used to initialize the signature verifier.
     * @param verificationKeys verification keys
     */
    public OnePassSignatureCheck(PGPOnePassSignature onePassSignature, PGPPublicKeyRing verificationKeys) {
        this.onePassSignature = onePassSignature;
        this.verificationKeys = verificationKeys;
    }

    public void setSignature(PGPSignature signature) {
        this.signature = signature;
    }

    /**
     * Return the {@link PGPOnePassSignature} object.
     *
     * @return onePassSignature
     */
    public PGPOnePassSignature getOnePassSignature() {
        return onePassSignature;
    }

    /**
     * Return the {@link OpenPgpV4Fingerprint} of the signing key.
     *
     * @return signing key fingerprint
     */
    public SubkeyIdentifier getSigningKey() {
        return new SubkeyIdentifier(verificationKeys, onePassSignature.getKeyID());
    }

    /**
     * Return the signature.
     *
     * @return signature
     */
    public PGPSignature getSignature() {
        return signature;
    }

    /**
     * Return the key ring used to verify the signature.
     *
     * @return verification keys
     */
    public PGPPublicKeyRing getVerificationKeys() {
        return verificationKeys;
    }
}
