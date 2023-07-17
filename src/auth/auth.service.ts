import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { AuthDto } from './dtos/auth.dto';
import { Tokens } from './types';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async signupLocal(dto: AuthDto): Promise<Tokens> {
    const hashedPassword = await this.hashDATA(dto.password);
    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        hashedPassword,
      },
    });

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateHashedRefreshToken(user.id, tokens.refresh_token);
    return tokens;
  }

  async signinLocal(dto: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }
    const passwordMatch = await bcrypt.compare(
      dto.password,
      user.hashedPassword,
    );
    if (!passwordMatch) {
      throw new BadRequestException('Invalid credentials');
    }

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateHashedRefreshToken(user.id, tokens.refresh_token);
    return tokens;
  }

  async logout(userId: number) {
    await this.prisma.user.updateMany({
      where: { id: userId, hashedRefreshToken: { not: null } },
      data: {
        hashedRefreshToken: null,
      },
    });
  }

  async refreshToken(userId: number, refresh_token: string): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (!user.hashedRefreshToken) {
      throw new BadRequestException('you are not logged in');
    }

    const refresh_token_match = await bcrypt.compare(
      refresh_token,
      user.hashedRefreshToken,
    );

    if (!refresh_token_match) {
      throw new BadRequestException('Access denied');
    }

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateHashedRefreshToken(user.id, tokens.refresh_token);
    return tokens;
  }

  hashDATA(data: string) {
    return bcrypt.hash(data, 10);
  }

  async getTokens(userId: number, email: string): Promise<Tokens> {
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(
        { sub: userId, email },
        {
          secret: this.configService.get<string>('ACCESS_TOKEN_SECRET'),
          expiresIn: 15 * 60,
        },
      ),
      this.jwtService.signAsync(
        { sub: userId, email },
        {
          secret: this.configService.get<string>('REFRESH_TOKEN_SECRET'),
          expiresIn: 7 * 24 * 60 * 60,
        },
      ),
    ]);
    return { access_token: at, refresh_token: rt };
  }

  async updateHashedRefreshToken(userId: number, refresh_token: string) {
    const hashedRefreshToken = await this.hashDATA(refresh_token);
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        hashedRefreshToken,
      },
    });
  }
}
