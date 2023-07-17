import { ExecutionContext, createParamDecorator } from '@nestjs/common';

export const GetCurrentUserProperties = createParamDecorator(
  (data: string | number, context: ExecutionContext) => {
    const request = context.switchToHttp().getRequest();
    console.log('test', request.user);
    return request.user[data];
  },
);
