/**
 * 接続回数制限ミドルウェア
 * @module rateLimit
 */

import * as createDebug from 'debug';
// tslint:disable-next-line:no-implicit-dependencies
import { NextFunction, Request, Response } from 'express';
import { TOO_MANY_REQUESTS } from 'http-status';
// tslint:disable-next-line:no-implicit-dependencies
import * as redis from 'ioredis';
import * as moment from 'moment';

const debug = createDebug('express-middleware:rateLimit');

export interface IRule {
    scope: string;
    aggregationUnitInSeconds: number;
}

export type ILimitExceededHandler = (numberOfRequests: number, req: Request, res: Response, next: NextFunction) => void;
export type IScopeGenerator = (req: Request) => string;
export interface IConfigurations {
    /**
     * redis cache接続クライアント
     * アプリケーション側で管理する
     */
    redisClient: redis.Redis;
    /**
     * 接続回数集計単位(秒)
     */
    aggregationUnitInSeconds: number;
    /**
     * 閾値
     */
    threshold: number;
    /**
     * 制限超過時の動作ハンドラー
     */
    limitExceededHandler?: ILimitExceededHandler;
    /**
     * スコープ生成メソッド
     * スコープをカスタマイズできるように(デフォルトはリクエストユーザーのIPアドレスを使用)
     */
    scopeGenerator?: IScopeGenerator;
}

/**
 * リクエスト数カウンターレポジトリー
 * @class
 */
export class RequestCounterRepository {
    public readonly redisClient: redis.Redis;

    constructor(redisClient: redis.Redis) {
        this.redisClient = redisClient;
    }

    public static CREATE_COUNTER_UNIT_PARAMS(now: Date, scope: string, aggregationUnitInSeconds: number) {
        const dateNow = moment(now);
        // tslint:disable-next-line:no-magic-numbers
        const aggregationUnit = parseInt(aggregationUnitInSeconds.toString(), 10);
        const validFrom = dateNow.unix() - dateNow.unix() % aggregationUnit;
        const validThrough = validFrom + aggregationUnit;

        return {
            identifier: `${scope}.${validFrom.toString()}`,
            validFrom: validFrom,
            validThrough: validThrough
        };
    }

    /**
     * 許可証数をカウントアップする
     * @param {Date} now 現在日時
     * @param {string} scope スコープ
     * @param {number} aggregationUnitInSeconds 集計単位(秒)
     */
    public async incr(now: Date, scope: string, aggregationUnitInSeconds: number): Promise<number> {
        const issueUnitParams = RequestCounterRepository.CREATE_COUNTER_UNIT_PARAMS(now, scope, aggregationUnitInSeconds);
        // tslint:disable-next-line:no-magic-numbers
        const ttl = parseInt(aggregationUnitInSeconds.toString(), 10);

        const results = await this.redisClient.multi()
            .incr(issueUnitParams.identifier, debug)
            .expire(issueUnitParams.identifier, ttl, debug)
            .exec();
        debug('results:', results);

        // tslint:disable-next-line:no-magic-numbers
        return parseInt(results[0][1], 10);
    }
}

export default (configurations: IConfigurations) => {
    const requestCounterRepo = new RequestCounterRepository(configurations.redisClient);

    // tslint:disable-next-line:no-suspicious-comment
    // TODO configurationsのバリデーション

    return async (req: Request, res: Response, next: NextFunction) => {
        // 接続回数をincrement
        const now = moment();
        const scope = (configurations.scopeGenerator !== undefined) ? configurations.scopeGenerator(req) : req.ip;
        const numberOfRequests = await requestCounterRepo.incr(
            now.toDate(),
            scope,
            configurations.aggregationUnitInSeconds
        );
        debug('comparing numberOfRequests and configurations.threshold...', numberOfRequests, configurations.threshold);
        const isLimitExceeded = (numberOfRequests > configurations.threshold);

        // res.setHeader('X-RateLimit-Limit', options.max);
        // res.setHeader('X-RateLimit-Remaining', req.rateLimit.remaining);

        if (!isLimitExceeded) {
            // 制限超過していなければOK
            next();

            return;
        }

        if (typeof configurations.limitExceededHandler === 'function') {
            configurations.limitExceededHandler(numberOfRequests, req, res, next);
        } else {
            res.setHeader('Retry-After', configurations.aggregationUnitInSeconds);
            res.status(TOO_MANY_REQUESTS).end('Too Many Requests');
        }
    };
};
