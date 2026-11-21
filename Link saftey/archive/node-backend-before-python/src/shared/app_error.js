class AppError extends Error {
  constructor(code, message, status = 500, details = []) {
    super(message);
    this.name = 'AppError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
  static invalid(message) { return new AppError('VALIDATION_ERROR', message, 400); }
  static tooLarge(message = 'Request body exceeds the allowed size.') { return new AppError('REQUEST_TOO_LARGE', message, 413); }
  static notFound() { return new AppError('NOT_FOUND', 'The requested resource was not found.', 404); }
  static unauthorized() { return new AppError('UNAUTHORIZED', 'A valid report access token is required.', 401); }
  static rateLimited() { return new AppError('RATE_LIMITED', 'Too many requests. Please wait and try again.', 429); }
}
module.exports = { AppError };
