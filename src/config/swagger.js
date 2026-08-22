import swaggerJSDoc from "swagger-jsdoc";

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Production Level Authentication API",
      version: "1.0.0",
      description:
        "A production-ready authentication API built with Node.js, Express, and Prisma.",
    },
    servers: [
      {
        url: `http://localhost:${process.env.PORT || 3000}/api/v1`,
        description: "Development server",
      },
    ],
    components: {
      securitySchemes: {
        BearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
        },
      },
      schemas: {
        User: {
          type: "object",
          properties: {
            id: {
              type: "string",
              format: "uuid",
              example: "716676c0-0fc4-4d58-ae24-baf33d865e12",
            },
            fullName: { type: "string", example: "John Doe" },
            username: { type: "string", example: "johndoe" },
            email: {
              type: "string",
              format: "email",
              example: "johndoe@example.com",
            },
            role: { type: "string", example: "USER" },
            emailVerified: { type: "boolean", example: true },
            createdAt: {
              type: "string",
              format: "date-time",
              example: "2023-01-01T00:00:00Z",
            },
          },
        },
        TokenPair: {
          type: "object",
          properties: {
            accessToken: {
              type: "string",
              example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            },
            refreshToken: {
              type: "string",
              example: "dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4gZXhhbXBsZQ==",
            },
          },
        },
        ApiError: {
          type: "object",
          properties: {
            success: { type: "boolean", example: false },
            error: {
              type: "object",
              properties: {
                status: { type: "string", example: "fail" },
                code: { type: "string", example: "VALIDATION_ERROR" },
                message: {
                  type: "string",
                  example: "Validation failed for the request.",
                },
                errors: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      field: { type: "string", example: "email" },
                      message: {
                        type: "string",
                        example:
                          "Email is required and must be a valid email address.",
                      },
                    },
                  },
                },
              },
            },
          },
        },
        ApiSuccess: {
          type: "object",
          properties: {
            success: { type: "boolean", example: true },
            message: { type: "string", example: "Operation successful." },
            data: { type: "object" },
          },
        },
      },
    },
    security: [{ BearerAuth: [] }],
  },
  apis: ["./src/modules/**/*.js"], // Path to the API docs
};

const swaggerSpec = swaggerJSDoc(options);

export default swaggerSpec;
