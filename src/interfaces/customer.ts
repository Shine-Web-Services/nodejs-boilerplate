interface ICustomerBasicInfo  {
    email: string   
    firstname?: string
    lastname?: string
}

export interface ICustomer {
    customer: ICustomerBasicInfo
    password?: string
}