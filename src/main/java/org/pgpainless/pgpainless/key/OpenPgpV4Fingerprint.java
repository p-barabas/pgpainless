/**
 *
 * Copyright 2018 Paul Schaub.
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
package org.pgpainless.pgpainless.key;

import javax.xml.bind.DatatypeConverter;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.encoders.Hex;

/**
 * This class represents an hex encoded, uppercase OpenPGP v4 fingerprint.
 */
public class OpenPgpV4Fingerprint implements CharSequence, Comparable<OpenPgpV4Fingerprint> {

    private final String fingerprint;

    /**
     * Create an {@link OpenPgpV4Fingerprint}.
     * @see <a href="https://xmpp.org/extensions/xep-0373.html#annoucning-pubkey">
     *     XEP-0373 §4.1: The OpenPGP Public-Key Data Node about how to obtain the fingerprint</a>
     * @param fingerprint hexadecimal representation of the fingerprint.
     */
    public OpenPgpV4Fingerprint(String fingerprint) throws PGPException {
        if (fingerprint == null) {
            throw new NullPointerException("Fingerprint MUST NOT be null.");
        }
        String fp = fingerprint.trim().toUpperCase();
        if (!isValid(fp)) {
            throw new PGPException("Fingerprint " + fingerprint +
                    " does not appear to be a valid OpenPGP v4 fingerprint.");
        }
        this.fingerprint = fp;
    }

    public OpenPgpV4Fingerprint(byte[] bytes) throws PGPException {
        this(new String(bytes, Charset.forName("UTF-8")));
    }

    public OpenPgpV4Fingerprint(PGPPublicKey key) throws PGPException {
        this(Hex.encode(key.getFingerprint()));
        if (key.getVersion() != 4) {
            throw new PGPException("Key is not a v4 OpenPgp key.");
        }
    }

    public OpenPgpV4Fingerprint(PGPSecretKey key) throws PGPException {
        this(key.getPublicKey());
    }

    public OpenPgpV4Fingerprint(PGPPublicKeyRing ring) throws PGPException {
        this(ring.getPublicKey());
    }

    public OpenPgpV4Fingerprint(PGPSecretKeyRing ring) throws PGPException {
        this(ring.getPublicKey());
    }

    /**
     * Check, whether the fingerprint consists of 40 valid hexadecimal characters.
     * @param fp fingerprint to check.
     * @return true if fingerprint is valid.
     */
    private boolean isValid(String fp) {
        return fp.matches("[0-9A-F]{40}");
    }

    /**
     * Return the key id of the OpenPGP public key this {@link OpenPgpV4Fingerprint} belongs to.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-12.2">
     *     RFC-4880 §12.2: Key IDs and Fingerprints</a>
     * @return key id
     */
    public long getKeyId() {
        byte[] bytes = DatatypeConverter.parseHexBinary(this.toString());
        byte[] lower8Bytes = Arrays.copyOfRange(bytes, 12, 20);
        ByteBuffer byteBuffer = ByteBuffer.allocate(8);
        byteBuffer.put(lower8Bytes);
        byteBuffer.flip();
        return byteBuffer.getLong();
    }

    @Override
    public boolean equals(Object other) {
        if (other == null) {
            return false;
        }

        if (!(other instanceof CharSequence)) {
            return false;
        }

        return this.toString().equals(other.toString());
    }

    @Override
    public int hashCode() {
        return fingerprint.hashCode();
    }

    @Override
    public int length() {
        return fingerprint.length();
    }

    @Override
    public char charAt(int i) {
        return fingerprint.charAt(i);
    }

    @Override
    public CharSequence subSequence(int i, int i1) {
        return fingerprint.subSequence(i, i1);
    }

    @Override
    public String toString() {
        return fingerprint;
    }

    @Override
    public int compareTo(OpenPgpV4Fingerprint openPgpV4Fingerprint) {
        return fingerprint.compareTo(openPgpV4Fingerprint.fingerprint);
    }
}
