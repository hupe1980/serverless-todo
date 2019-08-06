import 'source-map-support/register';
import {
    APIGatewayProxyEvent,
    APIGatewayProxyHandler,
    APIGatewayProxyResult,
} from 'aws-lambda';
import * as middy from 'middy';
import { cors } from 'middy/middlewares';

import { CreateTodoRequest } from '../../requests/CreateTodoRequest';
import { createTodo } from '../../businessLogic/todos';
import { createLogger } from '../../utils/logger';

const logger = createLogger('createTodoHandler');

const createTodoHandler: APIGatewayProxyHandler = async (
    event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> => {
    logger.info('Create a todo', event);

    const newTodo: CreateTodoRequest = JSON.parse(event.body);
    const authorization = event.headers.Authorization;
    const split = authorization.split(' ');
    const jwtToken = split[1];

    const newItem = await createTodo(newTodo, jwtToken);
    return {
        statusCode: 201,
        body: JSON.stringify({
            newItem,
        }),
    };
};

export const handler = middy(createTodoHandler).use(
    cors({ credentials: true }),
);
