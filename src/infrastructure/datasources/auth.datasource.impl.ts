import { BcryptAdapter } from "../../config";
import { UserModel } from "../../data/mongodb";
import { AuthDatasource, CustomError, RegisterUserDto, UserEntity } from "../../domain";



export class AuthDatasourceImpl implements AuthDatasource {
  async register(registerUserDto: RegisterUserDto): Promise<UserEntity> {

    const { name, email, password } = registerUserDto;

    try {

      //1. verificar si el correo existe
      const existsEmail = await UserModel.findOne({ email });
      if (existsEmail) {
        throw CustomError.badRequest('User already exists');
      }


      //2. hash de contraseña
      const user = new UserModel({ name, email, password: BcryptAdapter.hash(password) });

      await user.save();

      //3. mapear la respuesta a nuestra entidad
      return new UserEntity(
        user.id,
        name,
        email,
        user.password,
        user.role,
      )

    } catch (error) {
      if (error instanceof CustomError) {
        throw error;
      }
      throw CustomError.internalServer();
    }



  }

}
