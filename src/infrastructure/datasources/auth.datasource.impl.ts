import { UserMapper } from "..";
import { BcryptAdapter } from "../../config";
import { UserModel } from "../../data/mongodb";
import { AuthDatasource, CustomError, GetAndDeleteUserDto, LoginUserDto, RegisterUserDto, UpdateUserDto, UserEntity } from "../../domain";



//* type para declarar las funciones de dependencias y no tenerlas ocultas
type HashFunction = (password: string) => string;
type ConpareFunction = (password: string, hashed: string) => boolean;


export class AuthDatasourceImpl implements AuthDatasource {

  constructor(
    private readonly hashPassword: HashFunction = BcryptAdapter.hash,  //BcryptAdapter.hash le da valor por defecto para no tener que enviarlo
    private readonly comparePassword: ConpareFunction = BcryptAdapter.compare,
  ) { }
  async update(updateUserDto: UpdateUserDto): Promise<UserEntity> {
    const { id, ...rest } = updateUserDto;

    try {

      if (!id || !rest) {
        throw CustomError.badRequest('Invalid update data');
      }

      //1. verificar si el correo existe
      const existsEmail = await UserModel.findOne({ email: rest.email });
      if (existsEmail) {
        throw CustomError.badRequest('User already exists');
      }

      if (rest.password) {
        rest.password = this.hashPassword(rest.password);
      }

      const user = await UserModel.findByIdAndUpdate(id, rest, { new: true });

      return UserMapper.userEntityFromObject(user as UserEntity)

    } catch (error) {
      if (error instanceof CustomError) {
        throw error;
      }
      throw CustomError.internalServer();
    }
  }


  async login(loginUserDto: LoginUserDto): Promise<UserEntity> {
    const { email, password } = loginUserDto;

    try {

      //1. verificar si el usuario existe
      const user = await UserModel.findOne({ email });
      if (!user) {
        throw CustomError.badRequest('User not exists');
      }

      //2. verificar la contraseña hasheada
      const isMatchPassword = this.comparePassword(password, user.password);
      if (!isMatchPassword) {
        throw CustomError.badRequest('Invalid credentials')
      }

      return UserMapper.userEntityFromObject(user)

    } catch (error) {
      if (error instanceof CustomError) {
        throw error;
      }
      throw CustomError.internalServer();
    }
  }


  async register(registerUserDto: RegisterUserDto): Promise<UserEntity> {

    const { name, email, password } = registerUserDto;

    try {

      //1. verificar si el correo existe
      const existsEmail = await UserModel.findOne({ email });
      if (existsEmail) {
        throw CustomError.badRequest('User already exists');
      }


      //2. hash de contraseña
      const user = new UserModel({ name, email, password: this.hashPassword(password) });

      await user.save();

      //3. mapear la respuesta a nuestra entidad
      return UserMapper.userEntityFromObject(user)

    } catch (error) {
      if (error instanceof CustomError) {
        throw error;
      }
      throw CustomError.internalServer();
    }
  }

  async delete(getAndDeleteUserDto: GetAndDeleteUserDto): Promise<UserEntity> {

    const { id } = getAndDeleteUserDto;

    try {

      //1. verificar si el usuario existe
      const user = await UserModel.findByIdAndUpdate(id, { status: false }, { new: true });
      if (!user) {
        throw CustomError.badRequest('User not exists');
      }

      //2. mapear la respuesta a nuestra entidad
      return UserMapper.userEntityFromObject(user)

    } catch (error) {
      if (error instanceof CustomError) {
        throw error;
      }
      throw CustomError.internalServer();
    }
  }

}
