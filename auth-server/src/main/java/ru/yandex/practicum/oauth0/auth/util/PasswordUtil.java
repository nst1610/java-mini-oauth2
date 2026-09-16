package ru.yandex.practicum.oauth0.auth.util;

import org.mindrot.jbcrypt.BCrypt;

public class PasswordUtil {
    private PasswordUtil() {}

    public static String hash(String plain) {
        if (!acceptable(plain)) {
            throw new IllegalArgumentException();
        }
        return BCrypt.hashpw(plain, BCrypt.gensalt(12));
    }

    public static boolean matches(String plain, String hash) {
        if (!acceptable(plain) || hash == null) {
            return false;
        }
        return BCrypt.checkpw(plain, hash);
    }

    private static boolean acceptable(String plain) {
        return plain != null && !plain.isEmpty();
    }
}
