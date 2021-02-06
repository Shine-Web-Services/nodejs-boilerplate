import { Router } from 'express'
import auth from './auth'
import { TestController } from '../controllers'
// Init router and path
const router = Router()

// Add sub-routes
router.use('/auth', auth)
router.get('/', TestController.test)

// Export the base-router
export default router
