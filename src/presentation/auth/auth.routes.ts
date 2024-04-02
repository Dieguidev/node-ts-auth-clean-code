



import { Router } from "express";
import { AuthController } from "./auth.controller";
import { AuthDatasourceImpl, AuthRepositoryImpl } from "../../infrastructure";



export class AuthRoutes {


  static get routes(): Router {
    const router = Router();

    const database = new AuthDatasourceImpl();
    const authRepository = new AuthRepositoryImpl(database)

    const controller = new AuthController(authRepository);

    router.post('/login', controller.loginUser)
    router.post('/register', controller.registerUser)


    return router;
  }
}
