import { createHash } from 'crypto';

export function generateDeviceId(userAgent: string, ipAddress: string): string {
    return createHash('sha256').update(`${userAgent}-${ipAddress}`).digest('hex');
}

export function getLowerCasedFullName(firstName: string, lastName: string): string {
    return `${firstName?.trim()} ${lastName?.trim()}`.toLowerCase();
}
