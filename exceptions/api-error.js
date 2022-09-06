module.exports = class ApiError extends Error {
    status;
    error;

    constructor(status, message, errors) {
        super(message);
        this.status = status;
        this.error = errors;
    }

    static UnauthorizedError() {
        return new ApiError(401, 'User unauthorized');
    }

    static BadRequest(message, errors = []) {
        return new ApiError(400, message, errors);
    }
};
