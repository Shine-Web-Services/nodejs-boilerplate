import {IBaseSchema} from './'
export interface IUser extends IBaseSchema  {
    _id: string
    firstName?: string
    lastName?: string
    email: string
    password: string
    loginToken?: string
    forgotToken?: string
    verificationToken?: string
    lastLogin?: string
    status: number
}