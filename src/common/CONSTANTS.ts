export const enum Tokens {
    ACCESS_TOKEN_COOKIE_NAME = 'access_token',
    REFRESH_TOKEN_COOKIE_NAME = 'refresh_token',
}

// checks if a string has only letters, numbers, spaces, apostrophes, dots and dashes
export const NAME_REGEX = /(^[\p{L}\d'\.\s\-]*$)/u;

export const BCRYPT_HASH = /^\$2[aby]?\$[0-9]{2}\$[./A-Za-z0-9]{53}$/;

export const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export const MAX_PREV_PASSWORDS = 3 as const;

export const PASSWORD_SALT_COUNT = 10 as const;