package is.citizen.sdk.enums;

public enum AccessType {
    NAME         (1 << 0), // 1
    DOB          (1 << 1), // 2
    POB          (1 << 2), // 4
    NATIONALITY  (1 << 3), // 8
    ADDRESS      (1 << 4), // 16
    PHONE        (1 << 5), // 32
    GENDER       (1 << 6), // 64
    EMAIL        (1 << 7), // 128
    CARD_ON_FILE (1 << 8), // 256

    WEB_ACCESS   (1 << 10), // 1024

    TOKEN_SIGNATURE (1 << 12), // 4096

    DISTANCE_10KM   (1 << 14),

    PHOTO_ID_1   (1 << 17),
    PHOTO_ID_2   (1 << 18),
    PHOTO_ID_3   (1 << 19),
    PHOTO_ID_4   (1 << 20),
    PHOTO_ID_5   (1 << 21),

    ENTITY_JWT_AUTHENTICATION_WEBSOCKET (1 << 23),
    ENTITY_JWT_AUTHENTICATION_WEBHOOK (1 << 24),

    ADDRESS_VALID1 (1 << 26),
    ADDRESS_VALID2 (1 << 27),
    ADDRESS_VALID3 (1 << 28),
    ADDRESS_VALID4 (1 << 29),
    ADDRESS_VALID5 (1 << 30);

    private final int value;

    private AccessType(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static boolean contains(int value, AccessType accessType) {
        return (value & accessType.getValue()) > 0;
    }

    public static boolean contains(int targetAccess, int accessToCheck) {
        for (AccessType accessType : AccessType.values()) {
            if ((accessToCheck & accessType.getValue()) > 0) {
                if ((targetAccess & accessType.getValue()) == 0) {
                    return false;
                }
            }
        }

        return true;
    }

    public static int add(int value, AccessType accessType) {
        if ((value & accessType.getValue()) > 0) {
            return value;
        }

        return (value + accessType.getValue());
    }

    public static int add(int currentAccess, int extraAccess) {
        if (verify(extraAccess)) {
            return currentAccess | extraAccess;
        }

        return currentAccess;
    }

    public static int remove(int value, AccessType accessType) {
        if ((value & accessType.getValue()) > 0) {
            return (value - accessType.getValue());
        }

        return value;
    }

    public static int all() {
        int value = 0;

        for (AccessType accessType : AccessType.values()) {
            value += accessType.getValue();
        }

        return value;
    }

    public static int none() {
        return 0;
    }

    // Check that an int is comprised only of the powers of two used above.
    public static boolean verify(int value) {

        if (value < 0) {
            return false;
        }

        for (AccessType accessType : AccessType.values()) {
            if ((value & accessType.getValue()) > 0) {
                value -= accessType.getValue();
            }
        }

        if (value != 0) {
            return false;
        }

        return true;
    }

    public static String toString(int value) {
        StringBuilder ret = new StringBuilder();

        for (AccessType accessType : AccessType.values()) {
            if ((value & accessType.getValue()) > 0) {
                if (ret.length() > 0) {
                    ret.append(",");
                }
                ret.append(accessType);
            }
        }

        return ret.toString();
    }
}
