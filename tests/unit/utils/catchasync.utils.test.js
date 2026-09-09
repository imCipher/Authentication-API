import catchAsync from "../../../src/utils/catchasync.js";
import ApiError from "../../../src/utils/ApiError.js";

describe("catchAsync Utility", () => {
  let req;
  let res;
  let next;

  // Reset mocks and initialize request/response objects before each test
  beforeEach(() => {
    req = {
      body: {},
      params: {},
      query: {},
      headers: {},
    };
    res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
      send: vi.fn().mockReturnThis(),
    };
    next = vi.fn();
  });

  describe("Middleware Wrapper Structure", () => {
    it("should return a standard Express middleware function with arity of 3 (req, res, next)", () => {
      const wrapped = catchAsync(async () => {});

      expect(typeof wrapped).toBe("function");
      expect(wrapped.length).toBe(3);
    });

    it("should forward req, res, and next arguments to the wrapped handler", async () => {
      const mockHandler = vi.fn().mockResolvedValue("success");
      const wrapped = catchAsync(mockHandler);

      wrapped(req, res, next);

      expect(mockHandler).toHaveBeenCalledTimes(1);
      expect(mockHandler).toHaveBeenCalledWith(req, res, next);
    });
  });

  describe("Successful Asynchronous Execution", () => {
    it("should complete without calling next(error) when handler resolves successfully", async () => {
      const handler = vi.fn().mockImplementation(async (_req, res) => {
        return res.status(200).json({ success: true });
      });

      const wrapped = catchAsync(handler);
      wrapped(req, res, next);

      // Drain the microtask queue to allow promise resolution
      await Promise.resolve();

      expect(handler).toHaveBeenCalledTimes(1);
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({ success: true });
      expect(next).not.toHaveBeenCalled();
    });

    it("should handle resolved promises that return no value (void / undefined)", async () => {
      const handler = vi.fn().mockResolvedValue(undefined);
      const wrapped = catchAsync(handler);

      wrapped(req, res, next);
      await Promise.resolve();

      expect(handler).toHaveBeenCalledTimes(1);
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe("Asynchronous Error Handling & Delegation", () => {
    it("should catch rejected promises and forward the error to next()", async () => {
      const error = new Error("Database connection lost");
      const handler = vi.fn().mockRejectedValue(error);

      const wrapped = catchAsync(handler);
      wrapped(req, res, next);

      // Allow the promise rejection to propagate to .catch(next)
      await Promise.resolve();

      expect(next).toHaveBeenCalledTimes(1);
      expect(next).toHaveBeenCalledWith(error);
    });

    it("should catch thrown errors inside an async handler function", async () => {
      const expectedError = ApiError.notFound("User not found");
      const handler = async () => {
        throw expectedError;
      };

      const wrapped = catchAsync(handler);
      wrapped(req, res, next);

      // Allow the promise rejection to propagate to .catch(next)
      await Promise.resolve();

      expect(next).toHaveBeenCalledTimes(1);
      expect(next).toHaveBeenCalledWith(expectedError);
      expect(next.mock.calls[0][0]).toBeInstanceOf(ApiError);
      expect(next.mock.calls[0][0].statusCode).toBe(404);
    });

    it("should forward errors when handler explicitly returns a rejected Promise", async () => {
      const validationError = ApiError.badRequest("Invalid input payload");
      const handler = () => Promise.reject(validationError);

      const wrapped = catchAsync(handler);
      wrapped(req, res, next);

      // Allow the promise rejection to propagate to .catch(next)
      await Promise.resolve();

      expect(next).toHaveBeenCalledTimes(1);
      expect(next).toHaveBeenCalledWith(validationError);
    });
  });

    describe("Express Pipeline Context & Real-world Simulation", () => {
    it("should intercept service errors and halt normal response sending", async () => {
      const authError = ApiError.unauthorized("Token expired");
      const mockAuthService = {
        validateSession: vi.fn().mockRejectedValue(authError),
      };

      // Simulates real controller behavior in src/modules/auth/auth.controller.js
      const controller = async (req, res) => {
        await mockAuthService.validateSession(req.headers.authorization);
        res.status(200).json({ status: "authenticated" });
      };

      req.headers.authorization = "Bearer expired-token";
      const wrapped = catchAsync(controller);
      wrapped(req, res, next);

      // Wait for the full async resolution chain to finish and invoke next()
      await vi.waitFor(() => {
        expect(next).toHaveBeenCalledWith(authError);
      });

      expect(mockAuthService.validateSession).toHaveBeenCalledWith(
        "Bearer expired-token",
      );
      expect(res.status).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
    });
  });

});
