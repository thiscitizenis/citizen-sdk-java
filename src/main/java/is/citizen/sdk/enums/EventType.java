package is.citizen.sdk.enums;

public enum EventType {

    USER_UPDATED_ADDRESS        (1 << 1),
    USER_UPDATED_NAME           (1 << 2),
    USER_UPDATED_ORIGIN         (1 << 3),
    USER_ADDED_PHONE            (1 << 4),
    USER_ADDED_SOCIAL_ACCOUNT   (1 << 5),
    USER_UPDATED_SOCIAL_ACCOUNT (1 << 6),
    USER_REGISTERED             (1 << 7),

    DOCUMENT_ADD                (1 << 12),
    DOCUMENT_GRANTED_FOR_REQ    (1 << 13),
    DOCUMENT_GRANTED_BY_USER    (1 << 14),
    DOCUMENT_ADD_PROFILEPIC     (1 << 15),

    TOKEN_CREATED_BY_REQ        (1 << 20),
    TOKEN_CREATED_FOR_USER      (1 << 21),
    TOKEN_GRANTED_FOR_REQ       (1 << 22),
    TOKEN_GRANTED_BY_USER       (1 << 23),
    TOKEN_GRANTED_WEB_ACCESS    (1 << 24),
    TOKEN_DECLINED_FOR_REQ      (1 << 25),
    TOKEN_DECLINED_BY_USER      (1 << 26),

    JWT_PASSWORD_LOGIN          (1 << 29),
    JWT_TOKEN_LOGIN             (1 << 30);

    private int value;

    EventType(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static boolean contains(int value, EventType type) {
        return (value & type.getValue()) > 0;
    }

    public static int all() {
        int value = 0;
        for (EventType type : EventType.values()) {
            value += type.getValue();
        }
        return value;
    }

    public static int add(int value, EventType type) {
        if (contains(value, type)) {
            return value;
        }
        return (value + type.getValue());
    }

    public static boolean verify(int value) {
        if (value < 0) {
            return false;
        }
        for (EventType type : EventType.values()) {
            if (contains(value, type)) {
                value -= type.getValue();
            }
        }
        return value == 0;
    }
}
