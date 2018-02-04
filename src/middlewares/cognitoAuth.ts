/**
 * Cognito認証ミドルウェア
 * @module cognitoAuth
 * @see https://aws.amazon.com/blogs/mobile/integrating-amazon-cognito-user-pools-with-api-gateway/
 */

import * as createDebug from 'debug';
// tslint:disable-next-line:no-implicit-dependencies
import { NextFunction, Request, Response } from 'express';
import { UNAUTHORIZED } from 'http-status';
import * as jwt from 'jsonwebtoken';
// tslint:disable-next-line:no-require-imports no-var-requires
const jwkToPem = require('jwk-to-pem');
import * as request from 'request-promise-native';

const debug = createDebug('express-middleware:cognitoAuth');

export interface IUser {
    sub: string;
    token_use: string;
    scope: string;
    scopes: string[];
    iss: string;
    exp: number;
    iat: number;
    version: number;
    jti: string;
    client_id: string;
    username?: string;
}

/**
 * cognito認可サーバーのOPEN ID構成インターフェース
 * @export
 * @interface
 */
export interface IOpenIdConfiguration {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    jwks_uri: string;
    response_types_supported: string[];
    subject_types_supported: string[];
    version: string;
    id_token_signing_alg_values_supported: string[];
    x509_url: string;
}

/**
 * トークンに含まれる情報インターフェース
 * @export
 * @interface
 */
export interface IPayload {
    sub: string;
    token_use: string;
    scope: string;
    iss: string;
    exp: number;
    iat: number;
    version: number;
    jti: string;
    client_id: string;
    username?: string;
}

/**
 * 公開鍵インターフェース
 * @export
 * @interface
 */
export interface IPems {
    [key: string]: string;
}

const pemsByIssuer: { [issuer: string]: IPems } = {};

export type IAuthorizedHandler = (user: IUser, token: string, req: Request, res: Response, next: NextFunction) => void;
export type IUnauthorizedHandler = (err: Error, req: Request, res: Response, next: NextFunction) => void;
export type ITokenDetecter = (req: Request) => Promise<string>;
/**
 * ミドルウェア設定インターフェース
 */
export interface IConfigurations {
    /**
     * 許可発行者リスト
     */
    issuers: string[];
    /**
     * 認証成功時の動作ハンドラー
     */
    authorizedHandler: IAuthorizedHandler;
    /**
     * 認証失敗時の動作ハンドラー
     */
    unauthorizedHandler?: IUnauthorizedHandler;
    /**
     * リクエストからどうトークンを検出するか
     */
    tokenDetecter?: ITokenDetecter;
}

export default (configurations: IConfigurations) => {
    return async (req: Request, res: Response, next: NextFunction) => {
        try {
            let token: string | null = null;
            if (typeof configurations.tokenDetecter === 'function') {
                token = await configurations.tokenDetecter(req);
            } else {
                // トークン検出方法の指定がなければ、ヘッダーからBearerトークンを取り出す
                if (typeof req.headers.authorization === 'string' && req.headers.authorization.split(' ')[0] === 'Bearer') {
                    token = req.headers.authorization.split(' ')[1];
                }
            }

            if (token === null) {
                throw new Error('authorization required');
            }

            const payload = await validateToken(token, {
                issuers: configurations.issuers,
                tokenUse: 'access' // access tokenのみ受け付ける
            });
            debug('verified! payload:', payload);

            const user: IUser = {
                ...payload,
                ...{
                    // アクセストークンにはscopeとして定義されているので、scopesに変換
                    scopes: (typeof payload.scope === 'string') ? payload.scope.split((' ')) : []
                }
            };

            configurations.authorizedHandler(user, token, req, res, next);
        } catch (error) {
            if (typeof configurations.unauthorizedHandler === 'function') {
                configurations.unauthorizedHandler(error, req, res, next);
            } else {
                res.status(UNAUTHORIZED).end('Unauthorized');
            }
        }
    };
};

export const URI_OPENID_CONFIGURATION = '/.well-known/openid-configuration';
async function createPems(issuer: string) {
    const openidConfiguration: IOpenIdConfiguration = await request({
        url: `${issuer}${URI_OPENID_CONFIGURATION}`,
        json: true
    }).then((body: any) => body);

    return request({
        url: openidConfiguration.jwks_uri,
        json: true
    }).then((body: any) => {
        debug('got jwks_uri', body);
        const pemsByKid: IPems = {};
        (<any[]>body.keys).forEach((key) => {
            pemsByKid[key.kid] = jwkToPem(key);
        });

        return pemsByKid;
    });
}

/**
 * トークンを検証する
 */
async function validateToken(token: string, verifyOptions: {
    issuers: string[];
    tokenUse?: string;
}): Promise<IPayload> {
    debug('validating token...', token);
    const decodedJwt = <any>jwt.decode(token, { complete: true });
    debug('decodedJwt:', decodedJwt);
    if (!decodedJwt) {
        throw new Error('Not a valid JWT token.');
    }

    // audienceをチェック
    // if (decodedJwt.payload.aud !== AUDIENCE) {
    //     throw new Error('invalid audience');
    // }

    // tokenUseが期待通りでなければ拒否
    // tslint:disable-next-line:no-single-line-block-comment
    /* istanbul ignore else */
    if (verifyOptions.tokenUse !== undefined) {
        if (decodedJwt.payload.token_use !== verifyOptions.tokenUse) {
            throw new Error(`Not a ${verifyOptions.tokenUse}.`);
        }
    }

    // 許可発行者リストになければinvalid
    if (verifyOptions.issuers.indexOf(decodedJwt.payload.iss) < 0) {
        throw new Error('Unknown issuer.');
    }

    // 公開鍵未取得であればcognitoから取得
    if (pemsByIssuer[decodedJwt.payload.iss] === undefined) {
        pemsByIssuer[decodedJwt.payload.iss] = await createPems(decodedJwt.payload.iss);
    }

    // トークンからkidを取り出して、対応するPEMを検索
    const pems = pemsByIssuer[decodedJwt.payload.iss];
    const pem = pems[decodedJwt.header.kid];
    if (pem === undefined) {
        throw new Error('Invalid access token.');
    }

    // 対応PEMがあればトークンを検証
    return new Promise<IPayload>((resolve, reject) => {
        jwt.verify(
            token,
            pem,
            {
                issuer: verifyOptions.issuers // 期待しているユーザープールで発行されたJWTトークンかどうか確認
                // audience: pemittedAudiences
            },
            (err, payload) => {
                if (err !== null) {
                    reject(err);
                } else {
                    // Always generate the policy on value of 'sub' claim and not for 'username' because username is reassignable
                    // sub is UUID for a user which is never reassigned to another user
                    resolve(<IPayload>payload);
                }
            }
        );
    });
}
