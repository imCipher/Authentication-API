/**
 * A utility function to catch errors in asynchronous route
 * handlers and pass them to the next middleware.
 * @param {Function} fn - The asynchronous function to wrap.
 * @returns {Function} A new function that wraps the original
 * function and catches any errors.
 */
const catchAsync = fn => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

export default catchAsync;
