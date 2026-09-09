import ApiResponse from "../../../src/utils/ApiResponse.js";

describe("ApiResponse", () => {
  let mockRes;

  // Helper to create an isolated mock Express response object
  const createMockResponse = () => {
    const res = {};
    res.status = vi.fn().mockReturnValue(res);
    res.json = vi.fn().mockImplementation(payload => payload);
    return res;
  };

  // Reset mocks before each test to ensure isolation
  beforeEach(() => {
    mockRes = createMockResponse();
  });

  describe("Constructor & Core Response Formatting", () => {
    it("should set HTTP status code and send formatted JSON", () => {
      const data = { id: "user-123", name: "Alice" };
      const response = new ApiResponse(
        mockRes,
        200,
        "Operation successful",
        data,
      );

      expect(mockRes.status).toHaveBeenCalledTimes(1);
      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledTimes(1);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: "Operation successful",
        data,
      });

      // Validates that constructor returns the res.json result
      expect(response).toEqual({
        success: true,
        message: "Operation successful",
        data,
      });
    });

    it("should default message and data to undefined and options to empty object", () => {
      new ApiResponse(mockRes, 200);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: undefined,
        data: undefined,
      });
    });

    it("should spread additional options into the final JSON payload", () => {
      const data = [{ id: 1 }, { id: 2 }];
      const options = {
        pagination: {
          page: 1,
          limit: 10,
          total: 2,
        },
        meta: {
          requestId: "req-abc-123",
        },
      };

      new ApiResponse(mockRes, 200, "List retrieved", data, options);

      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: "List retrieved",
        data,
        pagination: {
          page: 1,
          limit: 10,
          total: 2,
        },
        meta: {
          requestId: "req-abc-123",
        },
      });
    });
  });

  describe("Success status flag calculation", () => {
    it.each([
      [200, true],
      [201, true],
      [204, true],
      [301, true],
      [304, true],
      [399, true],
      [100, false],
      [400, false],
      [401, false],
      [404, false],
      [500, false],
    ])(
      "should set success to %s for status code %i",
      (statusCode, expectedSuccess) => {
        new ApiResponse(mockRes, statusCode, "Status test");

        expect(mockRes.status).toHaveBeenCalledWith(statusCode);
        expect(mockRes.json).toHaveBeenCalledWith(
          expect.objectContaining({
            success: expectedSuccess,
          }),
        );
      },
    );
  });

  describe("Data payload variations", () => {
    it("should handle null data cleanly", () => {
      new ApiResponse(mockRes, 200, "Success with null data", null);

      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: "Success with null data",
        data: null,
      });
    });

    it("should handle array data cleanly", () => {
      const items = ["item1", "item2", "item3"];
      new ApiResponse(mockRes, 200, "Items list", items);

      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: "Items list",
        data: items,
      });
    });

    it("should handle primitive data types (boolean, number, string)", () => {
      new ApiResponse(mockRes, 200, "Count response", 42);

      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: "Count response",
        data: 42,
      });
    });
  });

  describe("Static Factory Methods", () => {
    describe("ApiResponse.success", () => {
      it("should send a 200 OK response with message and data", () => {
        const payload = { role: "ADMIN" };
        const result = ApiResponse.success(mockRes, "Success message", payload);

        expect(mockRes.status).toHaveBeenCalledWith(200);
        expect(mockRes.json).toHaveBeenCalledWith({
          success: true,
          message: "Success message",
          data: payload,
        });
        expect(result).toEqual({
          success: true,
          message: "Success message",
          data: payload,
        });
      });

      it("should use default parameters when only res and message are provided", () => {
        ApiResponse.success(mockRes, "Action completed");

        expect(mockRes.status).toHaveBeenCalledWith(200);
        expect(mockRes.json).toHaveBeenCalledWith({
          success: true,
          message: "Action completed",
          data: undefined,
        });
      });

      it("should forward custom options to the response payload", () => {
        ApiResponse.success(mockRes, "Success with options", null, {
          cached: true,
        });

        expect(mockRes.json).toHaveBeenCalledWith({
          success: true,
          message: "Success with options",
          data: null,
          cached: true,
        });
      });
    });

    describe("ApiResponse.created", () => {
      it("should send a 201 Created response with message and data", () => {
        const newUser = { id: "user-99", email: "user@example.com" };
        const result = ApiResponse.created(
          mockRes,
          "User created successfully",
          newUser,
        );

        expect(mockRes.status).toHaveBeenCalledWith(201);
        expect(mockRes.json).toHaveBeenCalledWith({
          success: true,
          message: "User created successfully",
          data: newUser,
        });
        expect(result).toEqual({
          success: true,
          message: "User created successfully",
          data: newUser,
        });
      });

      it("should allow passing custom options alongside created data", () => {
        ApiResponse.created(
          mockRes,
          "Resource created",
          { id: "item-1" },
          { version: "v1" },
        );

        expect(mockRes.status).toHaveBeenCalledWith(201);
        expect(mockRes.json).toHaveBeenCalledWith({
          success: true,
          message: "Resource created",
          data: { id: "item-1" },
          version: "v1",
        });
      });
    });

    describe("ApiResponse.noContent", () => {
      it("should send a 204 No Content response with undefined message and data", () => {
        const result = ApiResponse.noContent(mockRes);

        expect(mockRes.status).toHaveBeenCalledWith(204);
        expect(mockRes.json).toHaveBeenCalledWith({
          success: true,
          message: undefined,
          data: undefined,
        });
        expect(result).toEqual({
          success: true,
          message: undefined,
          data: undefined,
        });
      });
    });
  });
});
