import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { CreateUserRequest } from './dto/create-user.request';
import { UsersService } from './users.service';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { CurrentUser } from 'src/auth/current-user.decorator';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}
  @Post()
  async createUser(@Body() body: CreateUserRequest) {
    await this.usersService.createUser(body);
  }
  @Get(':id')
  async getUserById(@Param('id') id: string) {
    return this.usersService.getUser({ _id: id });
  }
  @Get()
  @UseGuards(JwtAuthGuard)
  async getUser(@CurrentUser() user) {
    return this.usersService.getAllUsers();
  }
}
