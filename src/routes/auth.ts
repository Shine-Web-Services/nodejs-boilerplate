import { Router } from 'express'
import { AuthController } from  '../controllers'
import {
    registerValidation,
    loginValidation,
    forgotPasswordValidation,
    resetPasswordValidation,
} from '../validations'
const router = Router()
/* auth routes listing. */
router.post('/register', registerValidation, AuthController.register)
router.post('/login', loginValidation, AuthController.login)
router.post('/forgot-password', forgotPasswordValidation, AuthController.forgotPassword)
router.post('/reset-password', resetPasswordValidation, AuthController.resetPassword)
export default router
