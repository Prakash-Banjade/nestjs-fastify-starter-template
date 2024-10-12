import { SetMetadata } from "@nestjs/common";
import { Action } from "../types/global.type";
import { Subjects } from "src/auth-system/casl/casl-ability.factory/casl-ability.factory";

export interface AbilityRequiredRules {
    action: Action,
    subject: Subjects,
}

export const CHECK_ABILITY = 'check_ability'

export const ChekcAbilities = (...requirements: AbilityRequiredRules[]) => SetMetadata(CHECK_ABILITY, requirements); 