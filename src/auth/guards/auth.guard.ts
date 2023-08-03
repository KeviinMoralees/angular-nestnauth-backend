import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Observable } from 'rxjs';
import { jwtPayLoad } from '../interfaces/jwt-payload';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {

  // injectamos el servicio del paquete de npm que instalamos previamente
  constructor(private jwtService: JwtService, private authService:AuthService){}


  // el contexto se refiere a la peticion hhtp o a la ruta 
  async canActivate(context: ExecutionContext, ): Promise<boolean> {
    
    // objetemos toda la data de la request o la peticion 
    const request = context.switchToHttp().getRequest();
    // extraemos el token de la peticion mediante el metodo privado que hay al final de este codigo 
    const token = this.extractTokenFromHeader(request);

    // valida que haya un token , peor puede ser lo que sea
    if (!token) {
      throw new UnauthorizedException(`don't have token un request`);
    }

    try {
      const payload = await this.jwtService.verifyAsync<jwtPayLoad>(
        token,{secret: process.env.JWT_SEED}
      );

      const user =  await this.authService.findUserById(payload.id);
      if(!user) throw new UnauthorizedException('el usuario no existe')
      if(!user.isActive) throw new UnauthorizedException('el usuario no esta activo')


      request['user'] = user;
      
  
      // console.log(payload);
  
    } catch (error) {
      throw new UnauthorizedException();
    }
    

    // podemos cmprobar l;a data que nos esta llegando 
    // console.log(request);
    // console.log(token);
    

    return true;
  }

  // extraemos el token , cambiamos la parte de request.headers para que lo encontrar mas facil
  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
