/**
 * ベーシック認証ミドルウェア
 * @module basicAuth
 */

import * as basicAuth from 'basic-auth';
import * as createDebug from 'debug';
// tslint:disable-next-line:no-implicit-dependencies
import { NextFunction, Request, Response } from 'express';
import { UNAUTHORIZED } from 'http-status';

const debug = createDebug('express-middleware:basicAuth');

export type IUnauthorizedHandler = (req: Request, res: Response, next: NextFunction) => void;
export interface IConfigurations {
    /**
     * 認証ネーム
     */
    name?: string;
    /**
     * 認証パス
     */
    pass?: string;
    /**
     * 認証失敗時の動作ハンドラー
     */
    unauthorizedHandler?: IUnauthorizedHandler;
}

export default (configurations: IConfigurations) => {
    return (req: Request, res: Response, next: NextFunction) => {
        // ベーシック認証設定なければスルー
        if (configurations.name === undefined || configurations.pass === undefined) {
            next();

            return;
        }

        if (typeof configurations.name !== 'string' || typeof configurations.pass !== 'string') {
            next();

            return;
        }

        if (configurations.name.length === 0 || configurations.pass.length === 0) {
            next();

            return;
        }

        // 以下、ベーシック認証設定が有効な場合
        const user = basicAuth(req);
        debug('basic auth user:', user);
        // tslint:disable-next-line:no-single-line-block-comment
        /* istanbul ignore else */
        if (user !== undefined) {
            if (user.name === configurations.name && user.pass === configurations.pass) {
                // 認証情報が正しければOK
                next();

                return;
            }
        }

        if (typeof configurations.unauthorizedHandler === 'function') {
            configurations.unauthorizedHandler(req, res, next);
        } else {
            res.setHeader('WWW-Authenticate', 'Basic realm="Access to staging site"');
            res.status(UNAUTHORIZED).end('Unauthorized');
        }
    };
};
