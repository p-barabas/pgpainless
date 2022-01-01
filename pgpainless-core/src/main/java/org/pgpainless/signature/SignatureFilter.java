// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature;

import org.bouncycastle.openpgp.PGPSignature;

import javax.annotation.Nonnull;

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
}
