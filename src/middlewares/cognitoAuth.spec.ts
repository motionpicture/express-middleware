// tslint:disable:no-implicit-dependencies

/**
 * 認証ミドルウェアテスト
 * @ignore
 */

import * as assert from 'assert';
import { OK } from 'http-status';
import * as jwt from 'jsonwebtoken';
import * as nock from 'nock';
import * as sinon from 'sinon';

import * as cognitoAuth from './cognitoAuth';

// let scope: nock.Scope;
let sandbox: sinon.SinonSandbox;
const jwks = {
    keys: [
        {
            alg: 'RS256',
            e: 'AQAB',
            kid: 'kid',
            kty: 'RSA',
            n: '12345',
            use: 'sig'
        }
    ]
};
const URI_JWKS = '/.well-known/jwks.json';
let openidConfiguration = {
    jwks_uri: ''
};

const TOKEN_ISSUER = 'https://example.com';

before(() => {
    openidConfiguration = {
        jwks_uri: `${TOKEN_ISSUER}${URI_JWKS}`
    };
});

describe('cognitoAuth.default()', () => {
    let defaultConfiguration: any;

    beforeEach(() => {
        nock.cleanAll();
        nock.disableNetConnect();
        sandbox = sinon.sandbox.create();

        // cognitoからの公開鍵は取得できる前提で進める
        const pemSScope = nock(`${TOKEN_ISSUER}`);
        pemSScope.get(cognitoAuth.URI_OPENID_CONFIGURATION).once().reply(OK, openidConfiguration);
        pemSScope.get(URI_JWKS).once().reply(OK, jwks);

        defaultConfiguration = {
            issuers: [TOKEN_ISSUER],
            authorizedHandler: () => {
                //no op
            }
        };
    });

    afterEach(() => {
        nock.cleanAll();
        nock.enableNetConnect();
        sandbox.restore();
        defaultConfiguration = undefined;
    });

    it('bearerヘッダーがなければUNAUTHORIZEDステータスとなるはず', async () => {
        const params = {
            req: { headers: {} },
            res: { status: () => params.res, end: () => undefined },
            next: () => undefined
        };

        sandbox.mock(params.res).expects('status').once().returns(params.res);
        sandbox.mock(params.res).expects('end').once();

        const result = await cognitoAuth.default(defaultConfiguration)(<any>params.req, <any>params.res, params.next);
        assert.equal(result, undefined);
        sandbox.verify();
    });

    it('unauthorizedHandlerを指定すれば呼ばれるはず', async () => {
        defaultConfiguration.unauthorizedHandler = () => undefined;
        const params = {
            req: { headers: {} },
            res: {},
            next: () => undefined
        };

        sandbox.mock(defaultConfiguration).expects('unauthorizedHandler').once()
            .withExactArgs(sinon.match.instanceOf(Error), params.req, params.res, params.next);

        const result = await cognitoAuth.default(defaultConfiguration)(<any>params.req, <any>params.res, params.next);
        assert.equal(result, undefined);
        sandbox.verify();
    });

    it('トークンをデコードできなければUNAUTHORIZEDステータスとなるはず', async () => {
        const params = {
            req: { headers: { authorization: 'Bearer JWT' } },
            res: { status: () => params.res, end: () => undefined },
            next: () => undefined
        };

        sandbox.mock(jwt).expects('decode').once().returns(false);
        sandbox.mock(params.res).expects('status').once().returns(params.res);
        sandbox.mock(params.res).expects('end').once();

        const result = await cognitoAuth.default(defaultConfiguration)(<any>params.req, <any>params.res, params.next);
        assert.equal(result, undefined);
        sandbox.verify();
    });

    it('authorizationヘッダーが正しければauthorizedHandlerが呼ばれるはず', async () => {
        const decodedJWT = {
            header: { kid: jwks.keys[0].kid },
            payload: { token_use: 'access', scope: 'scope scope2', iss: TOKEN_ISSUER }
        };
        const params: any = {
            req: { headers: { authorization: 'Bearer JWT' } },
            res: {},
            next: () => undefined
        };

        sandbox.mock(jwt).expects('decode').once().returns(decodedJWT);
        // tslint:disable-next-line:no-magic-numbers
        sandbox.mock(jwt).expects('verify').once().callsArgWith(3, null, decodedJWT.payload);
        sandbox.mock(defaultConfiguration).expects('authorizedHandler').once();

        const result = await cognitoAuth.default(defaultConfiguration)(<any>params.req, <any>params.res, params.next);
        assert.equal(result, undefined);
        sandbox.verify();
    });

    it('kidに対応するPEMが見つからなければUNAUTHORIZEDステータスとなるはず', async () => {
        const decodedJWT = {
            header: { kid: 'unknownkid' },
            payload: { token_use: 'access', scope: 'scope scope2', iss: TOKEN_ISSUER }
        };
        const params: any = {
            req: { headers: { authorization: 'Bearer JWT' } },
            res: { status: () => params.res, end: () => undefined },
            next: () => undefined
        };

        sandbox.mock(jwt).expects('decode').once().returns(decodedJWT);
        sandbox.mock(jwt).expects('verify').never();
        sandbox.mock(params.res).expects('status').once().returns(params.res);
        sandbox.mock(params.res).expects('end').once();

        const result = await cognitoAuth.default(defaultConfiguration)(<any>params.req, <any>params.res, params.next);
        assert.equal(result, undefined);
        sandbox.verify();
    });

    it('もしscopeがpayloadに含まれなくてもスコープリストは初期化されるはず', async () => {
        const decodedJWT = {
            header: { kid: jwks.keys[0].kid },
            payload: { token_use: 'access', iss: TOKEN_ISSUER }
        };
        const params: any = {
            req: { headers: { authorization: 'Bearer JWT' } },
            res: {},
            next: () => undefined
        };

        sandbox.mock(jwt).expects('decode').once().returns(decodedJWT);
        // tslint:disable-next-line:no-magic-numbers
        sandbox.mock(jwt).expects('verify').once().callsArgWith(3, null, decodedJWT.payload);
        sandbox.mock(defaultConfiguration).expects('authorizedHandler').once();

        const result = await cognitoAuth.default(defaultConfiguration)(<any>params.req, <any>params.res, params.next);
        assert.equal(result, undefined);
        // assert(Array.isArray(params.req.user.scopes)); // scopesが配列として初期化されているはず
        sandbox.verify();
    });

    it('token_useがaccessでなければUNAUTHORIZEDステータスとなるはず', async () => {
        const decodedJWT = {
            header: { kid: jwks.keys[0].kid },
            payload: { token_use: 'invalid', scope: '' }
        };
        const params = {
            req: { headers: { authorization: 'Bearer JWT' } },
            res: { status: () => params.res, end: () => undefined },
            next: () => undefined
        };

        sandbox.mock(jwt).expects('decode').once().returns(decodedJWT);
        sandbox.mock(jwt).expects('verify').never();
        sandbox.mock(params.res).expects('status').once().returns(params.res);
        sandbox.mock(params.res).expects('end').once();

        const result = await cognitoAuth.default(defaultConfiguration)(<any>params.req, <any>params.res, params.next);
        assert.equal(result, undefined);
        sandbox.verify();
    });

    it('公開鍵が存在しなければUNAUTHORIZEDステータスとなるはず', async () => {
        const decodedJWT = {
            header: { kid: 'invalid' },
            payload: { token_use: 'access', scope: '' }
        };

        const params = {
            req: { headers: { authorization: 'Bearer JWT' } },
            res: { status: () => params.res, end: () => undefined },
            next: () => undefined
        };

        sandbox.mock(jwt).expects('decode').once().returns(decodedJWT);
        sandbox.mock(jwt).expects('verify').never();
        sandbox.mock(params.res).expects('status').once().returns(params.res);
        sandbox.mock(params.res).expects('end').once();

        const result = await cognitoAuth.default(defaultConfiguration)(<any>params.req, <any>params.res, params.next);
        assert.equal(result, undefined);
        sandbox.verify();
    });

    it('トークンのvefiryに失敗すればUNAUTHORIZEDステータスとなるはず', async () => {
        const decodedJWT = {
            header: { kid: jwks.keys[0].kid },
            payload: { token_use: 'access', scope: '', iss: TOKEN_ISSUER }
        };

        const params = {
            req: { headers: { authorization: 'Bearer JWT' } },
            res: { status: () => params.res, end: () => undefined },
            next: () => undefined
        };

        sandbox.mock(jwt).expects('decode').once().returns(decodedJWT);
        // tslint:disable-next-line:no-magic-numbers
        sandbox.mock(jwt).expects('verify').once().callsArgWith(3, new Error('verify error'));
        sandbox.mock(params.res).expects('status').once().returns(params.res);
        sandbox.mock(params.res).expects('end').once();

        const result = await cognitoAuth.default(defaultConfiguration)(<any>params.req, <any>params.res, params.next);
        assert.equal(result, undefined);
        sandbox.verify();
    });
});
