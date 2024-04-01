import { UserEntity } from "../entities/user.entity";
import { RegisterUserDto } from '../dtos/auth/register-user.dto';




export abstract class AuthDatasource {

  //todo
  // abstract login(loginUserDto: LoginUserDto):Promise<UserEntity>

  abstract register(registerUserDto:RegisterUserDto):Promise<UserEntity>

}
