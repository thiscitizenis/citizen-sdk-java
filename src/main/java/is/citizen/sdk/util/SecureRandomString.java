package is.citizen.sdk.util;

import java.security.SecureRandom;
import java.util.Objects;
import java.util.Random;

public class SecureRandomString {

    private final char[] symbols = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".toCharArray();

    private final Random random;

    private final char[] buf;

    public String nextString() {
        for (int idx = 0; idx < buf.length; ++idx)
            buf[idx] = symbols[random.nextInt(symbols.length)];
        return new String(buf);
    }

    public SecureRandomString(int length) {
        if (length < 1) throw new IllegalArgumentException();
        this.random = Objects.requireNonNull(new SecureRandom());
        this.buf = new char[length];
    }
}

