import express, { Request, Response, NextFunction } from 'express'
import cookieParser from 'cookie-parser'
import cors from 'cors'
import morgan from 'morgan'
import helmet from 'helmet'
import i18n from 'i18n'
import expressValidator from 'express-validator'
import { BAD_REQUEST } from 'http-status-codes'
import 'express-async-errors'   
import BaseRouter from './routes'
import logger from '@utilities/logger'
import './db'
import './extensions/response'
import { AuthController } from '@controller'
// Init express
const app = express()

app.use(express.json())
app.use(express.urlencoded({extended: true}))
app.use(cookieParser())
// app.use(i18n.init)
app.use(cors())
app.use(expressValidator({
    errorFormatter: (param, message, value) => {
        return {
            param,
            message,
            value,
        }
    },
}))
app.use(AuthController.initialize())
app.use((req, res, next) => {
    req.headers['if-none-match'] = 'no-match-for-this'
    next()
})
app.disable('etag')
// configure i18n
i18n.configure({
    locales: ['en'],
    directory: __dirname + '/locales',
    defaultLocale: 'en',
    objectNotation: true,
})
app.use(i18n.init)

// Show routes called in console during development
if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'))
}

// Security
if (process.env.NODE_ENV === 'production') {
    app.use(helmet())
}

// Add APIs
logger.info(process.env.API_BASE)
app.use('', BaseRouter)

// Print API errors
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    if (res.headersSent) {
        return next(err)
    }
    logger.error(err.message, err)
    return res.status(BAD_REQUEST).json({
        message: i18n.__('errors.somethingBadHappened'), 
        messageCode: 'somethingBadHappened',
        description: i18n.__('errors.badRequest'),
        error: err.message,
    })
})

// Export express instances
export default app
