// tslint:disable:no-implicit-dependencies
/**
 * ベーシック認証ミドルウェアテスト
 */
import * as assert from 'assert';
import { UNAUTHORIZED } from 'http-status';
import * as sinon from 'sinon';

import basicAuth from './basicAuth';

let sandbox: sinon.SinonSandbox;

describe('basicAuth()', () => {
    beforeEach(() => {
        sandbox = sinon.sandbox.create();
    });

    afterEach(() => {
        sandbox.restore();
    });

    it('ユーザーネームとパスワードが正しければnextが呼ばれるはず', async () => {
        const configurations = {
            name: 'username',
            pass: 'password',
            unauthorizedHandler: undefined
        };

        const authorization = `Basic ${new Buffer(`${configurations.name}:${configurations.pass}`, 'utf8').toString('base64')}`;
        const params = {
            req: { headers: { authorization: authorization } },
            res: {},
            next: () => undefined
        };

        sandbox.mock(params).expects('next').once().withExactArgs();

        const result = basicAuth(configurations)(<any>params.req, <any>params.res, params.next);
        assert.equal(result, undefined);
        sandbox.verify();
    });

    it(`ユーザーネームが間違っていれば${UNAUTHORIZED}でレスポンスが返るはず`, async () => {
        const configurations = {
            name: 'username',
            pass: 'password',
            unauthorizedHandler: undefined
        };

        const authorization = `Basic ${new Buffer(`${configurations.name}:invalidpass`, 'utf8').toString('base64')}`;
        const params = {
            req: { headers: { authorization: authorization } },
            res: {
                setHeader: () => undefined,
                status: () => undefined,
                end: () => undefined
            },
            next: () => undefined
        };

        sandbox.mock(params).expects('next').never();
        sandbox.mock(params.res).expects('setHeader').once();
        sandbox.mock(params.res).expects('status').once().withExactArgs(UNAUTHORIZED).returns(params.res);
        sandbox.mock(params.res).expects('end').once();

        const result = basicAuth(configurations)(<any>params.req, <any>params.res, params.next);
        assert.equal(result, undefined);
        sandbox.verify();
    });

    // tslint:disable-next-line:mocha-no-side-effect-code
    [undefined, {}, null, ''].forEach((nameOrPass) => {
        it(`ベーシック認証設定が ${nameOrPass} であれば、何もせずにnextが呼ばれるはず`, async () => {
            const configurations = {
                name: nameOrPass,
                pass: nameOrPass,
                unauthorizedHandler: undefined
            };

            const params = {
                req: {},
                res: {},
                next: () => undefined
            };

            sandbox.mock(params).expects('next').once().withExactArgs();

            const result = basicAuth(<any>configurations)(<any>params.req, <any>params.res, params.next);
            assert.equal(result, undefined);
            sandbox.verify();
        });
    });

    it('認証失敗時動作を指定すれば、実行されるはず', async () => {
        const configurations = {
            name: 'username',
            pass: 'password',
            unauthorizedHandler: () => undefined
        };

        const authorization = `Basic ${new Buffer(`${configurations.name}:invalidpass`, 'utf8').toString('base64')}`;
        const params = {
            req: { headers: { authorization: authorization } },
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
        sandbox.mock(configurations).expects('unauthorizedHandler').once();

        const result = basicAuth(configurations)(<any>params.req, <any>params.res, params.next);
        assert.equal(result, undefined);
        sandbox.verify();
    });
});
