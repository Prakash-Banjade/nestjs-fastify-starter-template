require('dotenv').config();
import {
    registerDecorator,
    ValidationArguments,
    ValidationOptions,
    ValidatorConstraint,
    ValidatorConstraintInterface,
} from 'class-validator';
import { isUUID } from 'class-validator';

const BACKEND_URL = process.env.BACKEND_URL;

@ValidatorConstraint({ async: false })
export class IsUuidOrUrlConstraint implements ValidatorConstraintInterface {
    validate(value: any, args: ValidationArguments) {
        if (typeof value !== 'string') return false;

        return isUUID(value) || value.startsWith(BACKEND_URL);
    }

    defaultMessage(args: ValidationArguments) {
        return `${args.property} must be either a valid UUID or a valid URL`;
    }
}

export function IsUuidOrUrl(validationOptions?: ValidationOptions) {
    return function (object: Object, propertyName: string) {
        registerDecorator({
            target: object.constructor,
            propertyName: propertyName,
            options: validationOptions,
            constraints: [],
            validator: IsUuidOrUrlConstraint,
        });
    };
}

export function isUuidOrUrl(value: any): boolean {
    if (typeof value !== 'string') return false;

    return isUUID(value) || value.startsWith(BACKEND_URL);
}

export function isBackendUrl(value: any): boolean {
    if (typeof value !== 'string') return false;

    return value.startsWith(BACKEND_URL);
}