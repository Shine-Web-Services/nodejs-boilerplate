export const userRoles = ['artist', 'member']
export const socialLoginTypes = ['linkedIn', 'facebook']
export const magnetoStoreObj = {
    auth: {
        tokenAuthUrl: process.env.MAGENTO_SERVER_BASE_URI + '/V1/integration/admin/token',
        authBody: {
            username: process.env.MAGENTO_API_USER,
            password: process.env.MAGENTO_API_PASSWORD
        }
    },
    customer: {
        url: process.env.MAGENTO_SERVER_BASE_URI + '/V1/customers',
    },
    headers: {
        'Content-Type': 'application/json',
    }
}