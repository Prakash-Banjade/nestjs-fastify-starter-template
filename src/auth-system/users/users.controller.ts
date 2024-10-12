import { Controller, Get, Body, Patch, Param, Delete, Query, UseInterceptors } from '@nestjs/common';
import { UsersService } from './users.service';
import { UpdateUserDto } from './dto/update-user.dto';
import { UsersQueryDto } from './dto/user-query.dto';
import { ApiTags } from '@nestjs/swagger';
import { CurrentUser } from 'src/common/decorators/user.decorator';
import { Action, AuthUser } from 'src/common/types/global.type';
import { TransactionInterceptor } from 'src/common/interceptors/transaction.interceptor';
import { ChekcAbilities } from 'src/common/decorators/abilities.decorator';

@ApiTags("Users")
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) { }

  // @Post()
  // create(@Body() createUserDto: CreateUserDto) {
  //   return this.usersService.create(createUserDto);
  // }

  @Get()
  @ChekcAbilities({subject: 'all', action: Action.READ})
  findAll(@Query() queryDto: UsersQueryDto) {
    return this.usersService.findAll(queryDto);
  }

  @Get('me')
  getMyInfo(@CurrentUser() currentUser: AuthUser) {
    return this.usersService.myDetails(currentUser);
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.usersService.findOne(id);
  }

  @Patch()
  @UseInterceptors(TransactionInterceptor)
  update(@Body() updateUserDto: UpdateUserDto, @CurrentUser() currentUser: AuthUser) {
    return this.usersService.update(updateUserDto, currentUser);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.usersService.remove(id);
  }
}
