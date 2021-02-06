import './load-env' // Must be the first import
import app from './server'
import logger from '@utilities/logger'
import https from 'https'
import fs from 'fs'

const port: number = Number(process.env.PORT) || 4000
const protocol = process.env.PROTOCOL || 'HTTP'
const sshKey = process.env.SSH_KEY || ''
const sshCert = process.env.SSH_CERT || ''

if(protocol == 'HTTPS') {
    https.createServer({
        key: fs.readFileSync(sshKey),
        cert: fs.readFileSync(sshCert)
    }, app)
        .listen(port, function () {
            logger.info('asd Server started on port: ' + port)
        })
} else {
    const host: string = process.env.HOST || 'localhost'
    app.listen(port, host, () => {
        logger.info('asd Server started on port: ' + port)
    })
}

// Start the server
