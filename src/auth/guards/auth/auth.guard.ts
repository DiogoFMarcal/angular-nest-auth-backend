import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Observable } from 'rxjs';
import { AuthService } from 'src/auth/auth.service';
import { JwtPayload } from 'src/auth/interfaces/jtw-payload';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor(private jwtService: JwtService,
              private authService: AuthService
    ) {

  }

  async canActivate(
    context: ExecutionContext,
  ): Promise<boolean> {

    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);

    console.log({ token });

    if (!token) {
      throw new UnauthorizedException();
    }

    try {
      const payload = await this.jwtService.verifyAsync<JwtPayload>(
        token,
        {
          secret: process.env.JWT_SECRET
        }
      );
      console.log({ payload });

      const user = await this.authService.findUserById(payload.id);

      if(!user){
        throw new UnauthorizedException('User does not exists');
      }
      if(!user.isActive){
        throw new UnauthorizedException('User is not active ');
      }


      request['user'] = user;


    } catch (error) {
      throw new UnauthorizedException();
    }




    return Promise.resolve(true);
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization'].split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
