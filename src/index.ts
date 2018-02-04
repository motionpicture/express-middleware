/**
 * Express middlewares
 * @module
 */

import basicAuth from './middlewares/basicAuth';
import cognitoAuth from './middlewares/cognitoAuth';
import rateLimit from './middlewares/rateLimit';

export {
    basicAuth,
    cognitoAuth,
    rateLimit
};
