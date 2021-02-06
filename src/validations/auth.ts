import { NextFunction, Request, Response } from 'express'
import { HTTP_STATUS_CODES } from '@utilities/http-status-codes'
import { User } from '@schema'
import { socialLoginTypes, userRoles} from '@utilities/constants'
import { IUser } from 'src/interfaces'
/**
 * @description Login method validations (email, password)
 * @param req 
 * @param res 
 * @param next 
 */
export const loginValidation = (req: Request, res: Response, next: NextFunction) => {
    req.checkBody('email').notEmpty()
    req.checkBody('password').notEmpty()
    const errors = req.validationErrors(true)
    if (errors) {
        return res.status(HTTP_STATUS_CODES.UnprocessableEntity).json({errors})
    }
    next()
}
/**
 * @description email validation
 * @param req 
 * @param res 
 * @param next 
 */
export const emailValidation  = async (req: Request, res: Response, next: NextFunction) => {
    req.checkBody('email', req.__('validations.required', 'Email')).notEmpty().isEmail().withMessage(req.__('validations.invalidEmail'))
    const errors = req.validationErrors(true)
    if (errors) {
        return res.status(HTTP_STATUS_CODES.UnprocessableEntity).json({errors})
    }
    next()
}
/**
 * @description forgot password validation
 * @param req 
 * @param res 
 * @param next 
 */
export const forgotPasswordValidation = async (req: Request, res: Response, next: NextFunction) => {
    req.checkBody('email', req.__('validations.required', 'Email')).notEmpty().isEmail().withMessage(req.__('validations.invalidEmail')) 
    const errors = req.validationErrors(true)
    if (errors) {
        return res.status(HTTP_STATUS_CODES.UnprocessableEntity).json({errors})
    }
    next()
}
/**
 * @description reset password validation
 * @param req 
 * @param res 
 * @param next 
 */
export const resetPasswordValidation = async (req: Request, res: Response, next: NextFunction) => {
    req.checkBody('token').notEmpty()
    req.checkBody('password').notEmpty()
    const errors = req.validationErrors(true)
    if (errors) {
        return res.status(HTTP_STATUS_CODES.UnprocessableEntity).json({errors})
    }
    next()
}
/**
 * @description register validation
 * @param req 
 * @param res 
 * @param next 
 */
export const registerValidation = async (req: Request, res: Response, next: NextFunction) => {
    
    req.checkBody('email', req.__('validations.required', 'Email')).notEmpty().isEmail().withMessage(req.__('validations.invalidEmail'))
    req.checkBody('password', req.__('validations.required', 'Password')).notEmpty()
        .matches('^(?=.*)(?=.*[a-z])(?=.*[A-Z]).{8,}$').withMessage(req.__('validations.passwordNotMatch'))
    //TODO to true tnc

    const errors = req.validationErrors(true)
    if (errors) {
        return res.status(HTTP_STATUS_CODES.UnprocessableEntity).json({ errors })
    }
    // check if email exist
    const emailExist = await User.find({email: req.body.email}).exec()
    if (emailExist && emailExist.length > 0) {
        return res.status(HTTP_STATUS_CODES.BadRequest).json({
            errors: {
                email: {
                    param: 'email',
                    message: req.__('validations.duplicateEmail'),
                    value: req.body.email,
                },
            },
            messageCode: 'duplicateEmail',
        })
    }
    // check if username exist
    const usernameExist: IUser | null = await User.findOne({username: { '$regex': new RegExp(['^', req.body.username, '$'].join(''), 'i') }}).exec()
    if (usernameExist) {
        return res.status(HTTP_STATUS_CODES.BadRequest).json({
            errors: {
                name: {
                    param: 'name',
                    message: req.__('validations.duplicateUsername'),
                    value: req.body.name,
                },
            },
            messageCode: 'duplicateUsername',
        })
    }

    next()
}
