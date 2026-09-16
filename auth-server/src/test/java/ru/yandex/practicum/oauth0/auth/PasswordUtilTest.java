package ru.yandex.practicum.oauth0.auth;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;
import ru.yandex.practicum.oauth0.auth.util.PasswordUtil;

class PasswordUtilTest {
    @Test
    void correctPasswordMatchesAndWrongPasswordDoesNot() {
        String hash = PasswordUtil.hash("pass");
        assertTrue(PasswordUtil.matches("pass", hash));
        assertFalse(PasswordUtil.matches("wrong", hash));
        assertFalse(PasswordUtil.matches(null, hash));
    }

    @Test
    void bcryptLimitIsMeasuredInBytesAndDoesNotAcceptTruncatedPasswords() {
        String limit = "я".repeat(36);
        String hash = PasswordUtil.hash(limit);
        assertTrue(PasswordUtil.matches(limit, hash));
    }
}
