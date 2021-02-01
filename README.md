# Express middlewares for Node.js

[![npm (scoped)](https://img.shields.io/npm/v/@motionpicture/express-middleware.svg)](https://www.npmjs.com/package/@motionpicture/express-middleware)
[![CircleCI](https://circleci.com/gh/motionpicture/express-middleware.svg?style=shield)](https://circleci.com/gh/motionpicture/express-middleware)
[![Coverage Status](https://coveralls.io/repos/github/motionpicture/express-middleware/badge.svg)](https://coveralls.io/github/motionpicture/express-middleware)
[![Dependency Status](https://img.shields.io/david/motionpicture/express-middleware.svg)](https://david-dm.org/motionpicture/express-middleware)
[![Known Vulnerabilities](https://snyk.io/test/github/motionpicture/express-middleware/badge.svg)](https://snyk.io/test/github/motionpicture/express-middleware)
[![npm](https://img.shields.io/npm/dm/@motionpicture/express-middleware.svg)](https://nodei.co/npm/@motionpicture/express-middleware/)

## Table of contents

* [Usage](#usage)
* [License](#license)

## Usage

```sh
npm install @motionpicture/express-middleware
```

```js
var middlewares = require('@motionpicture/express-middleware');
```

### Environment variables

| Name    | Required | Value                | Purpose |
| ------- | -------- | -------------------- | ------- |
| `DEBUG` | false    | express-middleware:* | Debug   |

### Middlewares

| Name        | Purpose                                                               |
| ----------- | --------------------------------------------------------------------- |
| basicAuth   | Add a basic authentication.                                           |
| cognitoAuth | Add an authentication using Amazon Cognito User Pools.                |
| rateLimit   | Add a rate limiting using Redis Cache as request counting repository. |

## License

ISC
