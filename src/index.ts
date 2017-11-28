/**
 * Express middlewares
 * @module
 */

import basicAuth from './middlewares/basicAuth';
import rateLimit from './middlewares/rateLimit';

export {
    basicAuth,
    rateLimit
};
