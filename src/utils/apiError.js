export class ApiErrorResponse {

    constructor(statusCode, message){
        this.statusCode = statusCode;
        this.message = message;
    }

}