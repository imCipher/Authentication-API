import ApiError from "../Utils/ApiError.js";

/**
 * The accepted request sources for validation.
 */
const requestSources = ["body", "params", "query", "headers"];

/**
 * Formats Zod validation errors into a consistent structure.
 * @param {Array} issues - The array of Zod issues to format.
 * @param {string} source - The source of the request (body, params, query, headers).
 * @returns {Array} - An array of formatted error objects.
 */
const formatZodIssues = (issues, source) => {
  return issues.map(issue => ({
    field: issue.path.join(".") || source,
    message: issue.message,
  }));
};

/**
 * Middleware to validate incoming requests against provided Zod schemas.
 * @param {Object} schemas - An object containing Zod schemas for different request sources (body, params, query, headers).
 * @returns {Function} - Express middleware function for request validation.
 */
const validateRequest = (schemas = {}) => {
  return (req, res, next) => {
    const validated = {};

    for (const source of requestSources) {
      const schema = schemas[source];

      if (!schema) {
        continue; // Skip if no schema is defined for this source
      }

      const result = schema.safeParse(req[source]);

      if (!result.success) {
        return next(
          ApiError.badRequest(
            "Validation Failed",
            formatZodIssues(result.error.issues, source),
          ),
        );
      }

      validated[source] = result.data;
    }

    req.validated = {
      ...(req.validated || {}),
      ...validated,
    };
    return next();
  };
};

export default validateRequest;
