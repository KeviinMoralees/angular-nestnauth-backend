import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';

import * as bcryptjs from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { jwtPayLoad } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterUserDto, CreateUserDto, UpdateAuthDto, LoginDto } from './dto';

@Injectable()
export class AuthService {
  constructor(
    // con este modelo ya podemos hacer todo lo relacionado con la base de datos
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    // 1 - Encriptar la contraseña
    // 2 - Guardar usuario
    // 3 - Generar el jwt

    try {
      const { password, ...userData } = createUserDto;

      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData,
      });
      await newUser.save();
      const { password: _, ...user } = newUser.toJSON();

      return user;
    } catch (error) {
      console.log(error);
      if (error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} already exists!`);
      }
      throw new InternalServerErrorException(`algo ocurrio`);
    }
  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById(id: string) {
    const user = await this.userModel.findById(id);
    const { password, ...rest } = user.toJSON();
    return rest;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    // regresa user y token
    console.log(loginDto);
    const { email, password } = loginDto;

    // busca el usuario en la bd que coincida con ese email
    const user = await this.userModel.findOne({ email });
    // si no hay usuaio retorna error
    if (!user) {
      throw new UnauthorizedException(`Not Valid credentials - email`);
    }

    // si pasa el primer filtro y la contraseña no coinicide devuelve error
    if (!bcryptjs.compareSync(password, user.password)) {
      throw new UnauthorizedException(`Not Valid credentials - password`);
    }

    // si llego hasta aca todo va bien entonces devolvemos token

    const { password: _, ...resp } = user.toJSON();
    return {
      user: resp,
      token: this.getJwt({ id: user.id }),
    };
  }

  async register(registerUserDto: RegisterUserDto): Promise<LoginResponse> {
    const user = await this.create(registerUserDto);
    return {
      user: user,
      token: this.getJwt({ id: user._id }),
    };
  }

  getJwt(payload: jwtPayLoad) {
    const token = this.jwtService.sign(payload);
    return token;
  }
}
