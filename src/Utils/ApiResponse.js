/**
 * ApiResponse class to standardize API responses.
 * This class provides a consistent structure for sending success responses to the client.
 * It can be used to send success responses for various HTTP status codes like 200 (OK), 201 (Created), and 204 (No Content).
 * The class constructor takes in the response object, status code, message, data, and additional options.
 * It then sends a JSON response with the specified structure.
 */
class ApiResponse {
  constructor(
    res,
    statusCode,
    message = undefined,
    data = undefined,
    options = {},
  ) {
    this.statusCode = statusCode;
    this.success = statusCode >= 200 && statusCode < 400;
    this.message = message;
    this.data = data;
    this.options = options;

    return res.status(this.statusCode).json({
      success: this.success,
      message: this.message,
      data: this.data,
      ...this.options,
    });
  }

  /**
   * Sends a success response.
   *
   * @param {Object} res - The response object.
   * @param {string} message - The success message.
   * @param {Object|null} data - The data to include in the response.
   * @param {Object} options - Additional options for the response.
   * @returns {ApiResponse} The API response.
   */
  static success(res, message, data = undefined, options = {}) {
    return new ApiResponse(res, 200, message, data, options);
  }

  /**
   * Sends a created response (HTTP 201).
   *
   * @param {Object} res - The response object.
   * @param {string} message - The success message.
   * @param {Object|null} data - The data to include in the response.
   * @param {Object} options - Additional options for the response.
   * @returns {ApiResponse} The API response.
   */
  static created(res, message, data = undefined, options = {}) {
    return new ApiResponse(res, 201, message, data, options);
  }

  /**
   * Sends a no content response (HTTP 204).
   *
   * @param {Object} res - The response object.
   * @returns {ApiResponse} The API response.
   */
  static noContent(res) {
    return new ApiResponse(res, 204, undefined, undefined, {});
  }
}

export default ApiResponse;
