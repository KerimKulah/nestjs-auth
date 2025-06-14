import { HttpException, Injectable, InternalServerErrorException, NotFoundException } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { RefreshToken } from "./entities/refresh-token.entity";
import { LessThan, MoreThan, Repository } from "typeorm";
import { User } from "src/user/entities/user.entity";
import { v4 as uuidv4 } from 'uuid';
import { UnauthorizedException } from "@nestjs/common";
import { Cron } from "@nestjs/schedule";
import { Transactional } from "typeorm-transactional";
import { CurrentUser } from "src/common/decorators/currentuser.decorator";
import { Logger } from "@nestjs/common";

@Injectable()
export class RefreshTokenService {

    private readonly logger = new Logger(RefreshTokenService.name);

    constructor(
        @InjectRepository(RefreshToken) private readonly refreshTokenRepository: Repository<RefreshToken>
    ) { }

    // Refresh token oluştur ve kaydet
    @Transactional()
    async createRefreshTokenAndSave(user: User, ip: string, device: string): Promise<RefreshToken> {
        this.logger.debug(`Creating refresh token for user: ${user.id}, device: ${this.maskDevice(device)}`);

        try {
            // Mevcut cihaz ve ip için aktif refresh token varsa revoke et
            const existingToken = await this.refreshTokenRepository.findOne({
                where: { user, deviceInfo: device, ipAddress: ip, isRevoked: false, expiresAt: MoreThan(new Date()), },
            });

            if (existingToken) {
                this.logger.debug(`Revoking existing token for user: ${user.id}`);
                existingToken.isRevoked = true;
                await this.refreshTokenRepository.save(existingToken);
            }

            // Yeni token oluşturma
            const refreshToken = new RefreshToken();
            refreshToken.hash = uuidv4();
            refreshToken.expiresAt = new Date(Date.now() + Number(process.env.REFRESH_TOKEN_EXPIRES_IN));
            refreshToken.deviceInfo = device;
            refreshToken.ipAddress = ip;
            refreshToken.user = user;

            const savedToken = await this.refreshTokenRepository.save(refreshToken);
            this.logger.log(`Refresh token created for user: ${user.id}`);
            return savedToken;

        } catch (error) {
            this.logger.error(`Error creating refresh token for user: ${user.id}: ${error.message}`, error.stack);
            throw new InternalServerErrorException('Failed to create refresh token');
        }
    }

    // Refresh token'i hash ile revoke etme
    async revokeTokenByHash(hash: string): Promise<{ message: string }> {
        this.logger.debug(`Revoking token: ${this.maskToken(hash)}`);

        try {
            const token = await this.refreshTokenRepository.findOne({ where: { hash, isRevoked: false } });

            if (!token) {
                this.logger.warn(`Token not found or already revoked: ${this.maskToken(hash)}`);
                throw new NotFoundException('Refresh token not found or already revoked');
            }

            token.isRevoked = true;
            await this.refreshTokenRepository.save(token);

            this.logger.log(`Token revoked: ${this.maskToken(hash)}`);
            return { message: 'Refresh token revoked successfully' };

        } catch (error) {
            if (error instanceof NotFoundException) {
                throw error;
            }
            this.logger.error(`Error revoking token ${this.maskToken(hash)}: ${error.message}`, error.stack);
            throw new InternalServerErrorException('Failed to revoke refresh token');
        }
    }

    // Kullanıcının tüm tokenlarını revoke et (tüm cihazlardan çıkış)
    async revokeAllTokensByUser(user: User): Promise<{ message: string }> {
        if (!user) {
            this.logger.error('User parameter is null/undefined');
            throw new NotFoundException('User not found');
        }

        this.logger.debug(`Revoking all tokens for user: ${user.id}`);

        try {
            const tokens = await this.refreshTokenRepository.find({
                where: { user, isRevoked: false }
            });

            if (tokens.length === 0) {
                this.logger.debug(`No active tokens found for user: ${user.id}`);
                throw new NotFoundException('No active refresh tokens found for this user');
            }

            // Bulk update için optimize edilmiş
            await this.refreshTokenRepository.update(
                { user, isRevoked: false },
                { isRevoked: true }
            );

            this.logger.log(`All ${tokens.length} tokens revoked for user: ${user.id}`);
            return { message: 'All Refresh Tokens revoked successfully' };

        } catch (error) {
            if (error instanceof NotFoundException) {
                throw error;
            }
            this.logger.error(`Error revoking all tokens for user: ${user.id}: ${error.message}`, error.stack);
            throw new InternalServerErrorException('Failed to revoke all refresh tokens');
        }
    }

    // Refresh token doğrulama
    async validateRefreshToken(hash: string): Promise<RefreshToken> {
        this.logger.debug(`Validating token: ${this.maskToken(hash)}`);

        try {
            const refreshToken = await this.refreshTokenRepository.findOne({ where: { hash } });

            if (!refreshToken) {
                this.logger.warn(`Token validation failed - not found: ${this.maskToken(hash)}`);
                throw new NotFoundException('Refresh token not found');
            }

            if (refreshToken.isRevoked) {
                this.logger.warn(`Token validation failed - revoked: ${this.maskToken(hash)}`);
                throw new UnauthorizedException('Invalid refresh token');
            }

            if (refreshToken.expiresAt < new Date()) {
                this.logger.warn(`Token validation failed - expired: ${this.maskToken(hash)}`);
                throw new UnauthorizedException('Invalid refresh token');
            }

            if (refreshToken.usedAt) {
                this.logger.warn(`Token validation failed - already used: ${this.maskToken(hash)}`);
                throw new UnauthorizedException('Refresh token already used');
            }

            return refreshToken;

        } catch (error) {
            this.logger.error(`Error validating token: ${error.message}`, error.stack);
            throw error instanceof HttpException ? error : new InternalServerErrorException('Token validation failed');
        }
    }

    // Refresh token kullanıldı olarak işaretleme
    async markTokenAsUsed(token: RefreshToken): Promise<RefreshToken> {
        this.logger.debug(`Marking token as used: ${this.maskToken(token.hash)}`);

        try {
            if (token.usedAt) {
                this.logger.warn(`Token already used: ${this.maskToken(token.hash)}`);
                throw new UnauthorizedException('Token already used');
            }

            token.usedAt = new Date();
            const savedToken = await this.refreshTokenRepository.save(token);

            this.logger.debug(`Token marked as used: ${this.maskToken(token.hash)}`);
            return savedToken;

        } catch (error) {
            if (error instanceof UnauthorizedException) {
                throw error;
            }
            this.logger.error(`Error marking token as used: ${error.message}`, error.stack);
            throw new InternalServerErrorException('Failed to mark token as used');
        }
    }

    // Her gece revoke edilmiş ve süresi dolmuş tokenları temizle
    @Cron('0 0 * * *')
    async deleteRevokedTokens(): Promise<void> {
        this.logger.log('Starting cleanup of revoked and expired tokens');

        try {
            const result = await this.refreshTokenRepository.delete({
                isRevoked: true,
                expiresAt: LessThan(new Date())
            });

            this.logger.log(`Cleanup completed - deleted ${result.affected || 0} tokens`);

        } catch (error) {
            this.logger.error(`Error during token cleanup: ${error.message}`, error.stack);
        }
    }

    // Hash ile RefreshToken silme
    async deleteRefreshToken(hash: string): Promise<{ message: string }> {
        this.logger.debug(`Deleting token: ${this.maskToken(hash)}`);

        try {
            const refreshToken = await this.refreshTokenRepository.findOne({ where: { hash } });

            if (!refreshToken) {
                this.logger.warn(`Delete failed - token not found: ${this.maskToken(hash)}`);
                throw new NotFoundException('Refresh token not found');
            }

            await this.refreshTokenRepository.delete({ hash });
            this.logger.log(`Token deleted: ${this.maskToken(hash)}`);
            return { message: 'Refresh token deleted successfully' };

        } catch (error) {
            if (error instanceof NotFoundException) {
                throw error;
            }
            this.logger.error(`Error deleting token: ${error.message}`, error.stack);
            throw new InternalServerErrorException('Failed to delete refresh token');
        }
    }

    // Mevcut cihazda aktif refresh token'i al
    async getCurrentRefreshToken(user: User, device: string, ip: string): Promise<RefreshToken> {
        this.logger.debug(`Getting current token for user: ${user.id}`);

        try {
            const refreshToken = await this.refreshTokenRepository.findOne({
                where: { user, deviceInfo: device, ipAddress: ip, isRevoked: false }
            });

            if (!refreshToken) {
                this.logger.debug(`No current token found for user: ${user.id}`);
                throw new NotFoundException('Refresh token not found');
            }

            return refreshToken;

        } catch (error) {
            if (error instanceof NotFoundException) {
                throw error;
            }
            this.logger.error(`Error getting current token for user ${user.id}: ${error.message}`, error.stack);
            throw new InternalServerErrorException('Failed to get current refresh token');
        }
    }

    // Utility methods for privacy protection
    private maskToken(hash: string): string {
        return `${hash.substring(0, 8)}...${hash.substring(hash.length - 4)}`;
    }

    private maskDevice(device: string): string {
        return device.length > 20 ? `${device.substring(0, 15)}...` : device;
    }
}