import { BcryptAdapter } from "../../config";
import { UserModel } from "../../data/mongodb";
import { AuthDatasource, CustomError, RegisterUserDto, UserEntity } from "../../domain";
import { UserMapper } from "../mappers/user.mapper";

//* type para declarar las funciones de dependencias y no tenerlas ocultas
type HashFunction = (password: string) => string;
type ConpareFunction = (password: string, hashed: string) => boolean;


export class AuthDatasourceImpl implements AuthDatasource {

  constructor(
    private readonly hashPassword: HashFunction = BcryptAdapter.hash,  //BcryptAdapter.hash le da valor por defecto para no tener que enviarlo
    private readonly comparePassword: ConpareFunction = BcryptAdapter.compare,
  ) { }



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

}
