import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import * as bcrypt from 'bcryptjs';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { User } from 'src/users/schema/user.schema';
import { TokenPayload } from './token-payload.interface';
import { Response } from 'express';
@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  async generateTokens(user: User) {
    //Expiration datetimes
    const accessTokenExpiration = new Date();
    accessTokenExpiration.setMilliseconds(
      accessTokenExpiration.getMilliseconds() + 1000 * 60 * 15,
    );

    const refreshTokenExpiration = new Date();
    refreshTokenExpiration.setMilliseconds(
      refreshTokenExpiration.getMilliseconds() + 1000 * 60 * 60 * 24 * 7,
    );

    //User Id as the payload
    const tokenPayload: TokenPayload = { userId: user._id.toHexString() };

    //Token Generation
    const accessToken = this.jwtService.sign(tokenPayload, {
      secret: this.configService.getOrThrow('JWT_ACCESS_TOKEN_SECRET'),
      expiresIn: '15m',
    });

    const refreshToken = this.jwtService.sign(tokenPayload, {
      secret: this.configService.getOrThrow('JWT_REFRESH_TOKEN_SECRET'),
      expiresIn: '7d',
    });

    await this.usersService.updateUser(
      { _id: user._id },
      { $set: { refresh_token: await bcrypt.hash(refreshToken, 10) } },
    );

    //Attaching the tokens to cookies
    return {
      accessToken,
      accessTokenExpiration,
      refreshToken,
      refreshTokenExpiration,
    };
  }

  async verifyRefreshToken(refreshToken: string, userId: string) {
    try {
      const user = await this.usersService.getUser({ _id: userId });
      const compare = await bcrypt.compare(refreshToken, user.refresh_token!);
      if (!user || !compare)
        throw new UnauthorizedException('Error refreshing tokens');

      return user;
    } catch (error) {
      throw new UnauthorizedException('Error refreshing tokens');
    }
  }

  async login(user: User, response: Response) {
    const {
      accessToken,
      accessTokenExpiration,
      refreshToken,
      refreshTokenExpiration,
    } = await this.generateTokens(user);

    //Attaching the tokens to cookies
    response.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: this.configService.getOrThrow('NODE_ENV') === 'production',
      expires: accessTokenExpiration,
    });
    response.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: this.configService.getOrThrow('NODE_ENV') === 'production',
      expires: refreshTokenExpiration,
    });

    return { message: 'Log-in successful', email: user.email, _id: user._id };
  }

  async verifyUser(email: string, password: string) {
    try {
      const user = await this.usersService.getUser({ email });
      if (!user || !(await bcrypt.compare(password, user.password))) {
        throw new UnauthorizedException('Invalid Credentils');
      }
      return user;
    } catch (error) {
      throw new UnauthorizedException('Invalid Credentials');
    }
  }
}
