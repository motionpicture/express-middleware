// tslint:disable:no-implicit-dependencies
/**
 * rate limitミドルウェアテスト
 */
import * as assert from 'assert';
import { TOO_MANY_REQUESTS } from 'http-status';
import { Redis } from 'ioredis';
import * as sinon from 'sinon';
// tslint:disable-next-line:mocha-no-side-effect-code no-require-imports no-var-requires
const redis = require('ioredis-mock');

let redisClient: Redis;
import rateLimit from './rateLimit';

let sandbox: sinon.SinonSandbox;

describe('rateLimit()', () => {
    beforeEach(() => {
        redisClient = new redis({});
        sandbox = sinon.sandbox.create();
    });

    afterEach(() => {
        sandbox.restore();
    });

    it('制限に達していなければ、nextが呼ばれるはず', async () => {
        const configurations = {
            redisClient: redisClient,
            aggregationUnitInSeconds: 10,
            threshold: 1,
            onLimitExceeded: undefined,
            scopeGenerator: undefined
        };

        const params = {
            req: {},
            res: {},
            next: () => undefined
        };

        sandbox.mock(params).expects('next').once().withExactArgs();

        const result = await rateLimit(configurations)(<any>params.req, <any>params.res, params.next);
        assert.equal(result, undefined);
        sandbox.verify();
    });

    it(`制限を超過すれば、${TOO_MANY_REQUESTS}でレスポンスが返るはず`, async () => {
        const configurations = {
            redisClient: redisClient,
            aggregationUnitInSeconds: 10,
            threshold: 0,
            onLimitExceeded: undefined,
            scopeGenerator: undefined
        };

        const params = {
            req: {},
            res: {
                setHeader: () => undefined,
                status: () => undefined,
                end: () => undefined
            },
            next: () => undefined
        };

        sandbox.mock(params).expects('next').never();
        sandbox.mock(params.res).expects('setHeader').once();
        sandbox.mock(params.res).expects('status').once().withExactArgs(TOO_MANY_REQUESTS).returns(params.res);
        sandbox.mock(params.res).expects('end').once();

        const result = await rateLimit(configurations)(<any>params.req, <any>params.res, params.next);
        assert.equal(result, undefined);
        sandbox.verify();
    });

    it('制限超過時動作を指定すれば、実行されるはず', async () => {
        const configurations = {
            redisClient: redisClient,
            aggregationUnitInSeconds: 10,
            threshold: 0,
            limitExceededHandler: () => undefined,
            scopeGenerator: undefined
        };

        const params = {
            req: {},
            res: {
                setHeader: () => undefined,
                status: () => undefined,
                end: () => undefined
            },
            next: () => undefined
        };

        sandbox.mock(params).expects('next').never();
        sandbox.mock(params.res).expects('setHeader').never();
        sandbox.mock(params.res).expects('status').never();
        sandbox.mock(params.res).expects('end').never();
        sandbox.mock(configurations).expects('limitExceededHandler').once();

        const result = await rateLimit(configurations)(<any>params.req, <any>params.res, params.next);
        assert.equal(result, undefined);
        sandbox.verify();
    });

    it('スコープ生成メソッドを指定すれば、実行されるはず', async () => {
        const configurations = {
            redisClient: redisClient,
            aggregationUnitInSeconds: 10,
            threshold: 0,
            limitExceededHandler: undefined,
            scopeGenerator: () => 'scope'
        };

        const params = {
            req: {},
            res: {
                setHeader: () => undefined,
                status: () => undefined,
                end: () => undefined
            },
            next: () => undefined
        };

        sandbox.mock(params).expects('next').never();
        sandbox.mock(params.res).expects('setHeader').once();
        sandbox.mock(params.res).expects('status').once().withExactArgs(TOO_MANY_REQUESTS).returns(params.res);
        sandbox.mock(params.res).expects('end').once();
        sandbox.mock(configurations).expects('scopeGenerator').once();

        const result = await rateLimit(configurations)(<any>params.req, <any>params.res, params.next);
        assert.equal(result, undefined);
        sandbox.verify();
    });
});
