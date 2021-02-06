import './load-env' // Must be the first import
import app from './server'
import logger from '@utilities/logger'

logger.info(app)
// Start the server
const port = Number(process.env.PORT || 4000)
const host: string = process.env.HOST || 'localhost';
app.listen(port, host, () => {
    logger.info('asd Server started on port: ' + port)
})
