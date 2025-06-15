import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schema/user.schema';
import { FilterQuery, Model } from 'mongoose';
import { CreateUserRequest } from './dto/create-user.request';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
  ) {}

  async createUser(body: CreateUserRequest) {
    await new this.userModel({
      ...body,
      password: await bcrypt.hash(body.password, 10),
    }).save();
  }
  async getUser(query: FilterQuery<User>) {
    const user = (await this.userModel.findOne(query))?.toObject();
    if (!user) throw new NotFoundException('User not found!');
    return user;
  }
  async getAllUsers() {
    const users = await this.userModel.find({});
    return JSON.stringify(users);
  }
}
