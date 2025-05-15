export const enum Tokens {
    REFRESH_TOKEN_COOKIE_NAME = 'refresh_token',
    SUDO_ACCESS_TOKEN_COOKIE_NAME = 'sudo_access_token',
}

export const NAME_REGEX = /^[A-Za-z]+$/;
export const NAME_WITH_SPACE_REGEX = /^[A-Za-z]+( [A-Za-z]+)*$/;

export const BCRYPT_HASH = /^\$2[aby]?\$[0-9]{2}\$[./A-Za-z0-9]{53}$/;

export const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export const PHONE_NUMBER_REGEX = /^\+?(\d{1,3})?[-.\s]?(\(?\d{1,4}\)?)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}$/;

export const enum AuthMessage {
    INVALID_AUTH_CREDENTIALS = 'Invalid email or password',
    DEVICE_NOT_FOUND = 'Invalid device identity',
    TOKEN_EXPIRED = "TokenExpiredError",
    REPORT_NOT_PUBLISHED = "Report not published yet",
};

export const MAX_PREV_PASSWORDS = 3 as const;

export const PASSWORD_SALT_COUNT = 12 as const;

export const GRADE_REGEX = /^[A-F](\+|-|\*)*$/;

export const MAX_BOOK_ISSUE_LIMIT = 5 as const;

export const WEAK_PERCENTAGE_THRESHOLD = 50 as const;

export const MAX_RECENT_DAYS = 7 as const;

export const CHARGE_HEADS = {
    admissionFee: "Admission Fee",
    monthlyFee: "Monthly Fee",
    transportationFee: "Transportation Fee",
    libraryFine: "Library Fine",
};

export const SCHOOL_LEVEL_FACULTY_NAME = "School Level" as const;

// CACHE KEYS
export const enum CACHE_KEYS {
    CAY_ID = 'currentAcademicYearId'
}

export const thisSchool = {
    name: 'Abhyam SMS',
    address: 'Comming soon...',
    phone: '9800525463',
    logo: 'https://marketplace.canva.com/EAGLphtN1-E/1/0/1600w/canva-blue-modern-school-logo-bVNORNpm-c8.jpg',
} as const;