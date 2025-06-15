
import { Reflector } from "@nestjs/core";
import { Injectable } from "@nestjs/common";
import { CanActivate, ExecutionContext } from "@nestjs/common";
import { UnauthorizedException } from "@nestjs/common";
import { ForbiddenException } from "@nestjs/common";

@Injectable()
export class RolesGuard implements CanActivate {
    constructor(private readonly reflector: Reflector) { }

    canActivate(context: ExecutionContext): boolean {
        const requiredRoles = this.reflector.get<string[]>('roles', context.getHandler()) || [];
        const classRoles = this.reflector.get<string[]>('roles', context.getClass()) || [];

        const roles = [...requiredRoles, ...classRoles];

        // Eğer hiç rol tanımlı değilse erişime izin ver
        if (roles.length === 0) return true;

        const request = context.switchToHttp().getRequest();
        const user = request.user;

        if (!user) throw new UnauthorizedException('Kullanıcı doğrulanmamış');

        if (!user.roles || !roles.some(role => user.roles.includes(role))) {
            throw new ForbiddenException('Bu işlemi yapmaya yetkiniz yok');
        }

        return true;
    }
}