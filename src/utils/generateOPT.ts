import * as crypto from 'crypto'

export function generateOtp() {
    // Generate a random integer between 100000 and 999999 (inclusive)
    const min = 100000;
    const max = 999999;
    return crypto.randomInt(min, max + 1);
}