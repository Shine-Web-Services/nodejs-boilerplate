import { Request, Response } from 'express'
import { __ } from 'i18n'
/**
 * @category Controllers
 * @classdesc Test controller
 */
class Test {
    /**
    * @description Test
    */
    public test = async (req: Request, res: Response) => {
        return res.success({message: __('success.welcome')})
    };
}

export default new Test()
