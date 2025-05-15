import { Body, Controller, Get, Param, Patch } from "@nestjs/common";
import { ApiBearerAuth, ApiOperation, ApiParam, ApiResponse, ApiTags } from "@nestjs/swagger";
import { AccountsService } from "./accounts.service";
import { CheckAbilities } from "src/common/decorators/abilities.decorator";
import { Action, AuthUser, Role } from "src/common/types/global.type";
import { Toggle2faDto } from "./dto/accounts.dto";
import { CurrentUser } from "src/common/decorators/user.decorator";

@ApiBearerAuth()
@ApiTags('Accounts')
@Controller('accounts')
export class AccountsController {
    constructor(
        private readonly accountsService: AccountsService
    ) { }

    @Get('devices')
    @ApiOperation({
        summary: "Get the authenticated user's login devices",
        description: "Get all the login devices of the current user, including the current device (represented as signedIn: true)",
    })
    @ApiResponse({ status: 200, description: 'List of login devices' })
    @CheckAbilities({ subject: Role.USER, action: Action.READ })
    getDevices(@CurrentUser() currentUser: AuthUser) {
        return this.accountsService.getDevices(currentUser);
    }

    @Get('2fa/status')
    @ApiOperation({
        summary: "Get the 2FA status of the authenticated user",
        description: "Get the 2FA status of the current user. Returns date of 2fa enabled",
    })
    @ApiResponse({ status: 200, description: '2FA date' })
    @CheckAbilities({ subject: Role.USER, action: Action.READ })
    get2FaStatus(@CurrentUser() currentUser: AuthUser) {
        return this.accountsService.get2FaStatus(currentUser);
    }

    @Patch('devices/:deviceId/revoke')
    @ApiOperation({
        summary: "Revoke a login device",
        description: "Revoke a login device by its ID",
    })
    @ApiParam({ name: 'deviceId', description: 'The ID of the device to revoke' })
    @ApiResponse({ status: 200, description: 'Login device revoked successfully' })
    @ApiResponse({ status: 400, description: 'Cannot revoke current device' })
    @CheckAbilities({ subject: Role.USER, action: Action.UPDATE })
    revokeDevice(@Param('deviceId') deviceId: string, @CurrentUser() currentUser: AuthUser) {
        return this.accountsService.revokeDevice(deviceId, currentUser);
    }

    @Patch('2fa/toggle')
    @ApiOperation({
        summary: "Toggle 2FA",
        description: "Toggle 2FA of the current user",
    })
    @ApiResponse({ status: 200, description: '2FA status updated successfully' })
    @ApiResponse({ status: 404, description: 'No associated account found' })
    @CheckAbilities({ subject: Role.USER, action: Action.UPDATE })
    toggle2Fa(@Body() { toggle }: Toggle2faDto, @CurrentUser() currentUser: AuthUser) {
        return this.accountsService.toggle2Fa(toggle, currentUser);
    }
}