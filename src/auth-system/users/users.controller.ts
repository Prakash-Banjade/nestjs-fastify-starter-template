import { Controller, Get, Body, Patch, Param, Query, UseInterceptors } from '@nestjs/common';
import { UsersService } from './users.service';
import { UpdateUserDto } from './dto/update-user.dto';
import { UsersQueryDto } from './dto/user-query.dto';
import { ApiExcludeController, ApiTags } from '@nestjs/swagger';
import { CurrentUser } from 'src/common/decorators/user.decorator';
import { Action, AuthUser, Role } from 'src/common/types/global.type';
import { TransactionInterceptor } from 'src/common/interceptors/transaction.interceptor';
import { CheckAbilities } from 'src/common/decorators/abilities.decorator';

@ApiExcludeController()
@ApiTags("Users")
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) { }

  @Get()
  @CheckAbilities({ subject: Role.ADMIN, action: Action.READ })
  findAll(@Query() queryDto: UsersQueryDto) {
    return this.usersService.findAll(queryDto);
  }

  @Get('me')
  @CheckAbilities({ subject: Role.USER, action: Action.READ })
  getMyInfo(@CurrentUser() currentUser: AuthUser) {
    return this.usersService.myDetails(currentUser);
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.usersService.findOne(id);
  }

  @Patch()
  @UseInterceptors(TransactionInterceptor)
  @CheckAbilities({ subject: Role.USER, action: Action.UPDATE })
  update(@Body() updateUserDto: UpdateUserDto, @CurrentUser() currentUser: AuthUser) {
    return this.usersService.update(updateUserDto, currentUser);
  }
}
