// import logger from '@utilities/logger'
import {  IUser, IUserRole } from 'src/interfaces'
import { Request, Response } from 'express'
import bcrypt from 'bcryptjs'
import moment from 'moment'
import jwt from 'jsonwebtoken'
import passport from 'passport'
import randomize from 'randomatic'
import { ExtractJwt, Strategy } from 'passport-jwt'
import { __ } from 'i18n'
import { User} from '@schema'
import { comparePassword, sendEmail } from '@utilities/functions'
import { isNil } from 'lodash'
import logger from '@utilities/logger'

class Auth {
    /**
     * Initialize passport instance
     */
    public initialize = () => {
        passport.use('jwt', this.getStrategy())
        passport.session()
        return passport.initialize()
    }
    /**
     * Authenticate user for protected routes
     * @param  {function} callback Function for handle request after validate JWT token
     */
    public authenticate = 
    (callback: any) => {
        return passport.authenticate('jwt', { session: false, failWithError: true }, callback)
    }
    /**
     * @description New User registration
     * @param req 
     * @param res 
     * @param  {String} req.body.email email of user
     * @param  {String} req.body.password password of user
     * @param  {String} req.body.username user name
     */
    public register  = async (req: Request, res: Response) => {
        const token = randomize('A1', 32)
        const activationLink = process.env.CLIENT_APP_URL + 'verify-sign-up?token=' + token
        const {firstName, lastName, email, password, username, roleType} = req.body
        
        return new User({
            firstName: firstName || '',
            lastName: lastName || '',
            email,
            password: bcrypt.hashSync(password),
            status: 0,
            verificationToken: token,
            dateCreated: moment().toDate(),
            dateUpdated: moment().toDate(),
            isDeleted: 0,
        }).save()
            .then((user: IUser) => {
                const mailOptions = {
                    to: email,
                    subject: req.__('emails.welcomeEmailSubject'),
                    template: 'sign-up',
                    data: {
                        name: firstName || email,
                        link: activationLink,
                    },
                    from: process.env.MAIL_FROM

                }
                sendEmail(mailOptions)
                    .catch((err) => {
                        logger.info(err)
                    })
                return res.success({}, 'confirmRegistrationEmail')
            })
            .catch((err) => {
                return res.error(err, 'internalServerError')
            })
        
    };
    /**
     * @description user login
     * @param req 
     * @param res 
     * @param  {String} req.body.email email of user
     * @param  {String} req.body.password password of user
     */
    public login  = async (req: Request, res: Response) => {
        try {
            const {email, password} = req.body
            const token = randomize('A1', 32)
            let activationLink = '' 
            const userData: IUser | null = await this.getUser(email)
            // user  not found
            // TODO implement invalid credentials
            if (userData === null) { return res.badRequest(req.__('errors.credentialsMisMatch'), 'credentialsMisMatch') }
            
            // verify password
            const passVerify = await comparePassword(userData.password, password)
            if (passVerify === false) { 
                return res.badRequest(req.__('errors.credentialsMisMatch'), 'credentialsMisMatch')  
            }
            // Generate the token
            const jwtToken = this.generateToken(userData)
            return res.success({message: __('success.loginSuccess'), token: jwtToken, user: {username: userData.firstName}}, 'loginSuccess')
        } catch (error) {
            return res.error(req.__('errors.internalServerError'), 'internalServerError')
        }
        
    }
    /**
     * @description To validate if email already exists or not
     * @param req 
     * @param res 
     */
    public validateEmail = async (req: Request, res: Response) => {
        try {
            const emailExist = await User.find({email: req.body.email}).exec()
            if (emailExist && emailExist.length > 0) {
                return res.unprocessableEntity(req.__('errors.duplicateEmail'), 'duplicateEmail')
            }
            return res.ack()
            
        } catch (error) {
            return res.error(req.__('errors.internalServerError'), 'internalServerError')
        }
    }
    /**
     * Verify email confirmation link
     * @param  {Request} req 
     * @param  {Response} res
     * @returns {Object} {success: true} on success or error on failure
     */
    public verifySignUpLink = async (req: Request, res: Response) => {
        try {
            if (!req.body.token) {
                return res.badRequest(res.__('errors.badRequest'), 'badRequest')
            }
            /** Get email from token */
            const userEmailDetail: IUser | null = await User.findOne({verification_token: req.body.token}).exec()
            if (isNil(userEmailDetail)) {
                return res.badRequest(res.__('signUpLinkExpired'), 'signUpLinkExpired')
            }
            await User.updateOne({email: userEmailDetail.email}, {$set: {verification_token: '', status: 1}}).exec()
            // Generate the token
            const jwtToken = this.generateToken(userEmailDetail)
            return res.success({
                message: res.__('signUpEmailVerified'), token: jwtToken, user: {username: userEmailDetail.firstName}}, 'signUpEmailVerified')
        } catch (error) {
            return res.error(req.__('errors.internalServerError'), 'internalServerError')
        }
    }
    /**
     * Forgot password
     * @param  {Request} req 
     * @param  {Response} res
     * @returns {Object} {success: true} on success or error on failure
     */
    public forgotPassword = async (req: Request, res: Response) => {
        try {
            const { email } = req.body
            /** get email data*/
            const userDetail: IUser | null = await User.findOne({email}).exec()
            if (isNil(userDetail)) {
                return res.badRequest(res.__('errors.emailNotRegistered'), 'emailNotRegistered')
            }
            const token = randomize('A0', 8)
            const forgotLink = process.env.CLIENT_APP_URL  + 'reset-password?token=' + token
            await User.updateOne({email: req.body.email}, {$set: 
            {forgot_token: token, forgot_token_exp: moment().toDate()}}).exec()
            const mailOptions = {
                to: email,
                subject: req.__('emails.forgotEmailSubject'),
                template: 'forgot-password',
                data: {
                    name: userDetail.firstName || '',
                    link: forgotLink,
                },
            }
            sendEmail(mailOptions)
                .catch((err) => { 
                    logger.info(err)
                })
            return res.success({message:res. __('verifyLinkSent', '1')}, 'verifyLinkSent')
        } catch (error) {
            return res.error(req.__('errors.internalServerError'), 'internalServerError')
        }
    }
    /**
     * Reset password
     * @param  {Request} req 
     * @param  {Response} res
     * @returns {Object} {success: true} on success or error on failure
     */
    public resetPassword = async (req: Request, res: Response) => {
        
        try {
            const { token, password } = req.body
        
            /** Get expiry time */
            const expiryTime = moment().
                subtract({ hours: 1 }).toDate()
            const userData: IUser | null = await User.findOne(
            // {verification_token: token, forgot_token_exp: {
                {forgot_token: token, forgot_token_exp: {
                    '$gte': expiryTime
                }}).exec()
            if (isNil(userData)) {
                return res.badRequest(res.__('forgotLinkExpired'), 'forgotLinkExpired')
            }
            await User.updateOne({email:userData.email}, {$set: {forgot_token: '', password: bcrypt.hashSync(password) }}).exec()
            return res.success({
                message: res.__('passwordResetSuccess')}, 'passwordResetSuccess')
        } catch (error) {
            return res.error(req.__('errors.internalServerError'), 'internalServerError')
        }
    }
    /**
     * @description get user by email or username
     * @param {String} email
     */
    private getUser = async (email: string) => {
        return await User.findOne({
            $or: [
                {email},
                {username: email}
            ],
        }).exec()
    }
    
    /**
     * @description Generate Token
     * @param user 
     */
    private generateToken = (user: IUser): string => { 
        const expires = moment().utc().add({ hours: parseInt(process.env.JWT_TOKEN_VALIDITY as string, 10) }).unix()
        const token = jwt.sign({
            exp: expires,
            id: user._id,
        }, process.env.JWT_SECRET as string)
    
        return 'JWT ' + token
    }
    /**
     * Create strategy for Passport JWT
     * @returns Strategy
     * @private
     */
    private getStrategy = (): Strategy => {
        const params = {
            secretOrKey: process.env.JWT_SECRET,
            jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme('jwt'),
            passReqToCallback: true,
        }
        return new Strategy(params, (req: Request, payload: Record<string, unknown>, done: any) => {
            User.findOne({_id: payload.id, is_deleted: 0})
                .then((user) => {
                    if (isNil(user)) {
                        return done(null, false, { message: req.__('errors.userNotFound') })
                    }

                    return done(null, user)
                })
                .catch((err) => done(err))
        })
    }
}

export default new Auth()
