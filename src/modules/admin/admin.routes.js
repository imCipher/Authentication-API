import { Router } from "express";

import validateRequest from "../../middlewares/validator.middleware.js";
import { getUsersSchema } from "./admin.validation.js";
import adminController from "./admin.controller.js";
import {
  adminReadRateLimiter,
  adminSensitiveMutationRateLimiter,
  adminHeavyMaintenanceRateLimiter,
} from "../../middlewares/rateLimiter.middleware.js";
import { protect } from "../../middlewares/auth.middleware.js";
import { authorize } from "../../middlewares/rbac.middleware.js";

const router = Router();

/**
 * @swagger
 * tags:
 *   name: Admin
 *   description: Admin-only endpoints for managing users and system settings.
 */

router.use(protect); // Apply authentication middleware to all routes in this router

// Admin-only routes
router.use(authorize("admin")); // Apply role-based access control middleware to all routes in this router

/**
 * @swagger
 * /admin/users:
 *   get:
 *    summary: Fetch a paginated list of users with optional filters (Admin-only)
 *    description: Retrieve a paginated list of users with optional filtering, searching, and sorting. This endpoint is restricted to admin users only.
 *    tags: [Admin]
 *    parameters:
 *      - in: query
 *        name: page
 *        schema:
 *          type: integer
 *          default: 1
 *          minimum: 1
 *        description: Page number for pagination
 *      - in: query
 *        name: limit
 *        schema:
 *           type: integer
 *           default: 10
 *           minimum: 1
 *           maximum: 100
 *        description: Number of records to return per page (maximum 100)
 *      - in: query
 *        name: role
 *        schema:
 *           type: string
 *           enum: [USER, ADMIN]
 *        description: Filter users by account role (USER or ADMIN)
 *      - in: query
 *        name: status
 *        schema:
 *           type: string
 *           enum: [ACTIVE, SUSPENDED, DEACTIVATED]
 *        description: Filter users by account status (ACTIVE, SUSPENDED, DEACTIVATED)
 *      - in: query
 *        name: search
 *        schema:
 *           type: string
 *        description: Search term to match against email, username, or full name (max 100 characters)
 *      - in: query
 *        name: sortBy
 *        schema:
 *           type: string
 *           enum: [createdAt, fullName, email, username, lastLoginAt]
 *        description: Field to sort the results by (default: createdAt)
 *      - in: query
 *        name: sortOrder
 *        schema:
 *           type: string
 *           enum: [asc, desc]
 *           default: desc
 *        description: Order to sort the results by (default: desc)
 *    responses:
 *      200:
 *        description: Users retrieved successfully with pagination metadata.
 *        content:
 *          application/json:
 *            schema:
 *              allOf:
 *                  - $ref: '#/components/schemas/ApiSuccess'
 *                  - type: object
 *                      properties:
 *                          data:
 *                              type: object
 *                              properties:
 *                                  users:
 *                                     type: array
 *                                     items:
 *                                       $ref: '#/components/schemas/User'
 *                                  pagination:
 *                                     type: object
 *                                     properties:
 *                                        totalCount:
 *                                          type: integer
 *                                          example: 150
 *                                          description: Total number of users matching the query
 *                                        totalPages:
 *                                          type: integer
 *                                          example: 15
 *                                          description: Total number of pages of users matching the query
 *                                        currentPage:
 *                                          type: integer
 *                                          example: 1
 *                                          description: Current page of users matching the query
 *                                        limit:
 *                                          type: integer
 *                                          example: 10
 *                                          description: Number of users per page
 *                                        hasNextPage:
 *                                          type: boolean
 *                                          example: true
 *                                          description: Indicates if there is a next page of users
 *                                        hasPrevPage:
 *                                          type: boolean
 *                                          example: false
 *                                          description: Indicates if there is a previous page of users
 *      400:
 *        description: Validation failed. Invalid query parameters provided.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiValidationError'
 *      401:
 *        description: Unauthorized. Please provide valid authentication credentials.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiError'
 *      403:
 *        description: Forbidden. You do not have permission to access this resource.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiError'
 *      429:
 *        description: Too many requests. Rate limit exceeded.
 *        content:
 *          application/json:
 *            schema:
 *              $ref: '#/components/schemas/ApiError'
 */
router.get(
  "/users",
  adminReadRateLimiter,
  validateRequest(getUsersSchema),
  adminController.getUsers,
);

export default router;
