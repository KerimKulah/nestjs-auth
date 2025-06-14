
import { Reflector } from "@nestjs/core";
import { Injectable } from "@nestjs/common";
import { CanActivate, ExecutionContext } from "@nestjs/common";
import { UnauthorizedException } from "@nestjs/common";
import { ForbiddenException } from "@nestjs/common";

@Injectable()
export class RolesGuard implements CanActivate {
    constructor(private readonly reflector: Reflector) { }

    canActivate(context: ExecutionContext): boolean {
        
        const requiredRoles = this.reflector.get<string[]>('roles', context.getHandler());

        if (!requiredRoles || requiredRoles.length === 0) return true;

        const request = context.switchToHttp().getRequest();
        const user = request.user;

        console.log('RolesGuard:', { requiredRoles, user });


        if (!user) throw new UnauthorizedException('Kullanıcı doğrulanmamış');

        if (!user.roles || !requiredRoles.some(role => user.roles.includes(role))) {
            throw new ForbiddenException('Bu işlemi yapmaya yetkiniz yok');
        }

        return true;
    }
}