import { GetAndDeleteUserDto, LoginUserDto, RegisterUserDto, UpdateUserDto } from "..";

import { UserEntity } from "../entities/user.entity";





export abstract class AuthRepository {

  abstract login(loginUserDto: LoginUserDto):Promise<UserEntity>

  abstract register(registerUserDto:RegisterUserDto):Promise<UserEntity>;

  abstract update(updateUserDto: UpdateUserDto): Promise<UserEntity>;

  abstract delete(getAndDeleteUserDto: GetAndDeleteUserDto): Promise<UserEntity>;
}
